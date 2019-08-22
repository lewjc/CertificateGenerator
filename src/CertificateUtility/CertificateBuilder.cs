using NLog;
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

    public SecureRandom SecureRandom { get; private set; }

    private X509V3CertificateGenerator certificateGenerator;

    private AsymmetricCipherKeyPair keyPair;

    private ILogger logger;

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
    public CertificateBuilder(string signatureAlgorithm, ILogger logger)
    {
      this.signatureAlgorithm = signatureAlgorithm;
      this.logger = logger;
      keyStrength = DefaultCertificateParameters.KeyStrength;
      Init();
    }

    /// <summary>
    /// Allows for custom key strength and signature algorithm to be provided.
    /// </summary>
    /// <param name="keyStrength"></param>
    /// <param name="signatureAlgorithm"></param>
    public CertificateBuilder(int keyStrength, string signatureAlgorithm, ILogger logger)
    {
      this.keyStrength = keyStrength;
      this.signatureAlgorithm = signatureAlgorithm;
      this.logger = logger;
      Init();
    }

    /// <summary>
    /// Initialise builder.
    /// </summary>
    private void Init()
    {
      SecureRandom = new SecureRandom(new CryptoApiRandomGenerator());
      certificateGenerator = new X509V3CertificateGenerator();
      logger = LogManager.GetCurrentClassLogger();
      var keyGenerationParameters = new KeyGenerationParameters(SecureRandom, keyStrength);
      var keyPairGenerator = new RsaKeyPairGenerator();
      keyPairGenerator.Init(keyGenerationParameters);
      keyPair = keyPairGenerator.GenerateKeyPair();
      certificateGenerator.SetPublicKey(keyPair.Public);
    }

    /// <summary>
    /// Generates a random serial number to the certificate.
    /// </summary>
    /// <returns></returns>
    public CertificateBuilder AddSerialNumber()
    {
      return AddSerialNumber(BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), SecureRandom));
    }

    /// <summary>
    /// Adds the provided serial number to the certificate. 
    /// </summary>
    /// <param name="serial"></param>
    /// <returns></returns>
    public CertificateBuilder AddSerialNumber(BigInteger serial)
    {
      certificateGenerator.SetSerialNumber(serial);
      logger.Debug($"[ADD SERIAL NUMBER]");
      return this;
    }

    /// <summary>
    /// Adds the common name of the issuer to the certificate
    /// </summary>
    /// <param name="commonName"></param>
    /// <returns></returns>
    public CertificateBuilder AddIssuerCommonName(string commonName)
    {
      var issuer = Helper.StringToCNString(commonName);
      certificateGenerator.SetIssuerDN(new X509Name(issuer));
      logger.Debug($"[ISSUER CN] = {issuer}");
      return this;
    }

    /// <summary>
    /// Adds the common name of the certificate
    /// </summary>
    /// <param name="commonName"></param>
    /// <returns></returns>
    public CertificateBuilder AddSubjectCommonName(string commonName)
    {
      var subject = Helper.StringToCNString(commonName);
      certificateGenerator.SetSubjectDN(new X509Name(subject));
      logger.Debug($"[SUBJECT CN] = {subject}");
      return this;
    }

    /// <summary>
    /// Add a singular crl distribution point to the certificate
    /// </summary>
    /// <param name="url"></param>
    /// <returns></returns>
    public CertificateBuilder AddCRLDistributionPoint(string url)
    {
      return AddCRLDistributionPoints(new string[] { url });
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
        string url = urls[i];
        var name = new GeneralName(GeneralName.UniformResourceIdentifier, url.Trim());
        var dpName = new DistributionPointName(DistributionPointName.FullName, name);
        dps[i] = new DistributionPoint(dpName, null, null);
        logger.Debug($"[ADD DISTRIBUTION POINT] => {url}");
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
    public CertificateBuilder AddAKID(AsymmetricKeyParameter publicKey)
    {
      var akid = new AuthorityKeyIdentifierStructure(publicKey);
      certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, akid);
      logger.Debug($"[AUTHORITY KEY IDENTIFIER] {akid.ToString()}");
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
      logger.Debug($"[AUTHORITY LOCATION] {certificateUrl}");
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
      logger.Debug($"[CERTIFICATE VALID FROM] {notBefore.Date} [TO] {notAfter.Date}");
      return this;
    }

    /// <summary>
    /// Adds all extended key usages to the certficate
    /// </summary>
    /// <returns></returns>
    public CertificateBuilder AddExtendedKeyUsages()
    {
      return AddExtendedKeyUsages(new[] { KeyPurposeID.AnyExtendedKeyUsage });
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

      for (int idx = 0; idx < extendedKeyUsages.Length; idx++)
      {
        logger.Debug($"[EXTENDED KEY USAGE] {extendedKeyUsages[idx].ToString()}");
      }
      return this;
    }

    /// <summary>
    /// Makes the current certificate in the build chain into a CA by attaching the necessary Key Usages and Basic Constraints.
    /// </summary>
    public CertificateBuilder MakeCA()
    {
      AddBasicConstraints(true);
      AddKeyUsages((int)(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign));
      logger.Debug($"[MAKING CA]");
      return this;
    }

    /// <summary>
    /// Adds a subject key identifier to the certificate. This is a hash value of the public key.
    /// </summary>
    /// <returns></returns>
    public CertificateBuilder AddSKID()
    {
      var skid = new SubjectKeyIdentifierStructure(keyPair.Public);
      certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, skid);
      logger.Debug($"[ADD SUBJECT KEY IDENTIFIER]");
      return this;
    }

    /// <summary>
    /// Add key usages to the certificate
    /// </summary>
    /// <param name="keyUsages"> Integer of chained flags. EXAMPLE: X509KeyUsageFlags.One | X509KeyUsageFlags.Two</param>
    /// <returns></returns>
    public CertificateBuilder AddKeyUsages(int keyUsages)
    {
      var keyUsageCertSign = new KeyUsage(keyUsages);
      certificateGenerator.AddExtension(X509Extensions.KeyUsage.Id, false, keyUsageCertSign);
      return this;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="CA">Whether or not to add CA basic constraints.</param>
    /// <returns></returns>
    public CertificateBuilder AddBasicConstraints(bool CA = false)
    {
      certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, false, new BasicConstraints(CA));
      return this;
    }

    /// <summary>
    /// Generates the certificate. This should be used for root/self signed certfificates as they will have no issuer.
    /// </summary>
    /// <returns></returns>
    public X509Certificate GenerateRoot()
    {
      logger.Debug($"[GENERATING ROOT]");
      return Generate(keyPair.Private, out AsymmetricCipherKeyPair @params);
    }

    /// <summary>
    /// Generates the certificate. This should be used for root/self signed certfificates as they will have no issuer.
    /// This also returns the private key of the certificate generated.
    /// </summary>
    /// <returns></returns>
    public X509Certificate GenerateRootWithPrivateKey(out AsymmetricCipherKeyPair keyPair)
    {
      keyPair = this.keyPair;
      ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, keyPair.Private, SecureRandom);
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
    public X509Certificate Generate(AsymmetricKeyParameter issuerPrivateKey, out AsymmetricCipherKeyPair generatedKeyPair)
    {
      generatedKeyPair = keyPair;
      ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issuerPrivateKey, SecureRandom);
      return certificateGenerator.Generate(signatureFactory);
    }
  }
}
