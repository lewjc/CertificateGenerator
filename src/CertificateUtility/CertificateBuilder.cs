using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Security.Cryptography.X509Certificates;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace CertificateUtility
{
  public class CertificateBuilder
  {

    private readonly int keyStrength;

    private readonly string signatureAlgorithm;

    private SecureRandom secureRandom;

    private X509V3CertificateGenerator certificateGenerator;

    private AsymmetricCipherKeyPair keyPair;

    /// <summary>
    /// 
    /// </summary>
    public CertificateBuilder()
    {
      // Default Key Strength.
      keyStrength = DefaultCertificateParameters.KeyStrength;
      signatureAlgorithm = DefaultCertificateParameters.SignatureAlgorithm;
      Init();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="keyStrength"></param>
    public CertificateBuilder(int keyStrength)
    {
      this.keyStrength = keyStrength;
      signatureAlgorithm = DefaultCertificateParameters.SignatureAlgorithm;
      Init();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="signatureAlgorithm"></param>
    public CertificateBuilder(string signatureAlgorithm)
    {
      this.signatureAlgorithm = signatureAlgorithm;
      keyStrength = DefaultCertificateParameters.KeyStrength;
      Init();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="keyStrength"></param>
    /// <param name="signatureAlgorithm"></param>
    public CertificateBuilder(int keyStrength, string signatureAlgorithm)
    {
      this.keyStrength = keyStrength;
      this.signatureAlgorithm = signatureAlgorithm;
      Init();
    }

    /// <summary>
    /// 
    /// </summary>
    private void Init()
    {
      secureRandom = new SecureRandom(new VmpcRandomGenerator());
      certificateGenerator = new X509V3CertificateGenerator();
      var keyGenerationParameters = new KeyGenerationParameters(secureRandom, keyStrength);
      var keyPairGenerator = new RsaKeyPairGenerator();
      keyPairGenerator.Init(keyGenerationParameters);
      keyPair = keyPairGenerator.GenerateKeyPair();
    }

    public CertificateBuilder AddSerialNumber()
    {
      certificateGenerator.SetSerialNumber(BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));
      return this;
    }
    public CertificateBuilder AddSerialNumber(BigInteger serial)
    {
      certificateGenerator.SetSerialNumber(serial);
      return this;
    }

    public CertificateBuilder AddIssuerCommonName(string commonName)
    {
      certificateGenerator.SetIssuerDN(new X509Name(Helper.StringToCNString(commonName)));
      return this;
    }
    public CertificateBuilder AddSubjectCommonName(string commonName)
    {
      certificateGenerator.SetSubjectDN(new X509Name(Helper.StringToCNString(commonName)));
      return this;
    }

    public CertificateBuilder AddCRLDistributionPoint(string url)
    {
      var name = new GeneralName(GeneralName.UniformResourceIdentifier, url);
      var dpName = new DistributionPointName(DistributionPointName.FullName, name);
      var distributionPoint = new DistributionPoint(dpName, null, null);
      certificateGenerator.AddExtension(X509Extensions.CrlDistributionPoints, false, new CrlDistPoint(new[] { distributionPoint }));
      return this;
    }

    public CertificateBuilder AddCRLDistributionPoints(string[] urls)
    {
      var dps = new DistributionPoint[urls.Length];
      for (int i = 0; i < urls.Length; i++)
      {
        var name = new GeneralName(GeneralName.UniformResourceIdentifier, urls[i]);
        var dpName = new DistributionPointName(DistributionPointName.FullName, name);
        dps[i] = new DistributionPoint(dpName, null, null);
      }
      certificateGenerator.AddExtension(X509Extensions.CrlDistributionPoints, false, new CrlDistPoint(dps));
      return this;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="issuingCA">The Certificate of the CA issuing this cert.</param>
    /// <returns></returns>
    public CertificateBuilder AddAKID(X509Certificate issuingCA)
    {
      certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(issuingCA));
      return this;
    }

    public CertificateBuilder AddAuthorityInfoAccess(string certificateUrl)
    {
      var authAccess = new AuthorityInformationAccess(new AccessDescription(
        X509ObjectIdentifiers.CrlAccessMethod,
        new GeneralName(GeneralName.UniformResourceIdentifier, certificateUrl)));
      certificateGenerator.AddExtension(X509Extensions.AuthorityInfoAccess, false, authAccess);
      return this;
    }

    public CertificateBuilder AddValidityTime()
    {
      var notBefore = DateTime.UtcNow.Date;
      var notAfter = notBefore.AddYears(50);
      certificateGenerator.SetNotBefore(notBefore);
      certificateGenerator.SetNotAfter(notAfter);
      return this;
    }

    public CertificateBuilder AddValidityTime(DateTime notBefore, DateTime notAfter)
    {
      certificateGenerator.SetNotBefore(notBefore);
      certificateGenerator.SetNotAfter(notAfter);
      return this;
    }

    public CertificateBuilder AddExtendedKeyUsages()
    {
      certificateGenerator.AddExtension(oid: X509Extensions.ExtendedKeyUsage.Id,
        critical: false, extensionValue: new ExtendedKeyUsage(new[] { KeyPurposeID.AnyExtendedKeyUsage }));
      return this;
    }

    public CertificateBuilder AddExtendedKeyUsages(KeyPurposeID[] extendedKeyUsages)
    {
      certificateGenerator.AddExtension(oid: X509Extensions.ExtendedKeyUsage.Id,
        critical: false, extensionValue: new ExtendedKeyUsage(extendedKeyUsages));
      return this;
    }

    /// <summary>
    /// Makes the current certificate in the build chain into a CA by attaching the necessary Key Usages and Basic Constraints.
    /// </summary>
    public CertificateBuilder SetCA()
    {
      var keyUsageCertSign = new KeyUsage((int)(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign));

      certificateGenerator.AddExtension(X509Extensions.KeyUsage.Id, false, keyUsageCertSign);

      var caConstraint = new BasicConstraints(true);

      certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, false, caConstraint);

      return this;
    }

    /// <summary>
    /// Generates the certificate. This should be used for root/self signed certfificates as they will have no issuer.
    /// </summary>
    /// <returns></returns>
    public X509Certificate GenerateRoot()
    {
      ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, keyPair.Private, secureRandom);
      return certificateGenerator.Generate(signatureFactory);
    }

    /// <summary>
    /// Generates the certificate. This should be used for root/self signed certfificates as they will have no issuer.
    /// </summary>
    /// <returns></returns>
    public X509Certificate GenerateRootWithPrivateKey(out AsymmetricKeyParameter privateKey)
    {
      privateKey = keyPair.Private;
      ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, privateKey, secureRandom);
      return certificateGenerator.Generate(signatureFactory);
    }

    /// <summary>
    /// Generates the certificate using options provided in the chain.
    /// </summary>
    /// <param name="issuerPrivateKey">
    /// The private key of the CA issuing this certificate. Needed so that the certificates
    /// signature is valid.
    /// </param>
    /// <returns></returns>
    public X509Certificate Generate(AsymmetricKeyParameter issuerPrivateKey)
    {
      ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, keyPair.Private, secureRandom);
      return certificateGenerator.Generate(signatureFactory);
    }
  }
}
