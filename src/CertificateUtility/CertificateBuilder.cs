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
    /// Default constructer, uses default certificate parameters
    /// </summary>
    public CertificateBuilder()
    {
      // Default Key Strength.
      keyStrength = DefaultCertificateParameters.KeyStrength;
      signatureAlgorithm = DefaultCertificateParameters.SignatureAlgorithm;
      Init();
    }

    /// <summary>
    /// Allows for custom key strength to be provided.
    /// </summary>
    /// <param name="keyStrength"></param>
    public CertificateBuilder(int keyStrength)
    {
      this.keyStrength = keyStrength;
      signatureAlgorithm = DefaultCertificateParameters.SignatureAlgorithm;
      Init();
    }

    /// <summary>
    /// Allows for a custom signature algorithm to be provided.
    /// </summary>
    /// <param name="signatureAlgorithm"></param>
    public CertificateBuilder(string signatureAlgorithm)
    {
      this.signatureAlgorithm = signatureAlgorithm;
      keyStrength = DefaultCertificateParameters.KeyStrength;
      Init();
    }

    /// <summary>
    /// Allows for custom key strength and signature algorithm to be provided.
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
    /// Initialise builder.
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

    /// <summary>
    /// Generates a random serial number to the certificate.
    /// </summary>
    /// <returns></returns>
    public CertificateBuilder AddSerialNumber()
    {
      certificateGenerator.SetSerialNumber(BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));
      return this;
    }

    /// <summary>
    /// Adds the provided serial number to the certificate. 
    /// </summary>
    /// <param name="serial"></param>
    /// <returns></returns>
    public CertificateBuilder AddSerialNumber(BigInteger serial)
    {
      certificateGenerator.SetSerialNumber(serial);
      return this;
    }

    /// <summary>
    /// Adds the common name of the issuer to the certificate
    /// </summary>
    /// <param name="commonName"></param>
    /// <returns></returns>
    public CertificateBuilder AddIssuerCommonName(string commonName)
    {
      certificateGenerator.SetIssuerDN(new X509Name(Helper.StringToCNString(commonName)));
      return this;
    }

    /// <summary>
    /// Adds the common name of the certificate
    /// </summary>
    /// <param name="commonName"></param>
    /// <returns></returns>
    public CertificateBuilder AddSubjectCommonName(string commonName)
    {
      certificateGenerator.SetSubjectDN(new X509Name(Helper.StringToCNString(commonName)));
      return this;
    }

    /// <summary>
    /// Add a singular crl distribution point to the certificate
    /// </summary>
    /// <param name="url"></param>
    /// <returns></returns>
    public CertificateBuilder AddCRLDistributionPoint(string url)
    {
      return AddCRLDistributionPoints(new string[] {url});
    }

    /// <summary>
    /// Attaches multiple distribution points to the certificate currently in the chain.
    /// </summary>
    /// <param name="urls">A list of http CRL locations</param>
    /// <returns></returns>
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
    /// Adds the authority key identifier to the certificate being generated. This allows 2 leaf certificates with the same CN to be
    /// identified.
    /// </summary>
    /// <param name="issuingCA">The Certificate of the CA issuing this cert.</param>
    /// <returns></returns>
    public CertificateBuilder AddAKID(X509Certificate issuingCA)
    {
      certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(issuingCA));
      return this;
    }

    /// <summary>
    /// Adds the authority access information to the certificate, this specifies where the issuing certificate can be found.
    /// can be through ldap and http.
    /// </summary>
    /// <param name="certificateUrl"></param>
    /// <returns></returns>
    public CertificateBuilder AddAuthorityInfoAccess(string certificateUrl)
    {
      var authAccess = new AuthorityInformationAccess(new AccessDescription(
        X509ObjectIdentifiers.CrlAccessMethod,
        new GeneralName(GeneralName.UniformResourceIdentifier, certificateUrl)));
      certificateGenerator.AddExtension(X509Extensions.AuthorityInfoAccess, false, authAccess);
      return this;
    }

    /// <summary>
    /// Sets the default validty time to 50 years.
    /// </summary>
    /// <returns></returns>
    public CertificateBuilder AddValidityTime()
    {
     return AddValidityTime(DateTime.UtcNow.Date, DateTime.UtcNow.Date.AddYears(50));
    }

    /// <summary>
    /// Specify time that this certificate is valid from and is valid to.
    /// </summary>
    /// <param name="notBefore"></param>
    /// <param name="notAfter"></param>
    /// <returns></returns>
    public CertificateBuilder AddValidityTime(DateTime notBefore, DateTime notAfter)
    {
      certificateGenerator.SetNotBefore(notBefore);
      certificateGenerator.SetNotAfter(notAfter);
      return this;
    }

    /// <summary>
    /// Adds all extended key usages to the certficate
    /// </summary>
    /// <returns></returns>
    public CertificateBuilder AddExtendedKeyUsages()
    {
      certificateGenerator.AddExtension(oid: X509Extensions.ExtendedKeyUsage.Id,
        critical: false, extensionValue: new ExtendedKeyUsage(new[] { KeyPurposeID.AnyExtendedKeyUsage }));
      return this;
    }

    /// <summary>
    /// Add specific extended key usages to the certificate
    /// </summary>
    /// <param name="extendedKeyUsages"></param>
    /// <returns></returns>
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
    /// This also returns the private key of the certificate generated.
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
    /// <returns>Bouncy Castle Certificate with parameters based on the configured chain.</returns>
    public X509Certificate Generate(AsymmetricKeyParameter issuerPrivateKey)
    {
      ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, keyPair.Private, secureRandom);
      return certificateGenerator.Generate(signatureFactory);
    }
  }
}
