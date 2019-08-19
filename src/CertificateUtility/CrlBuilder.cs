using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;

namespace CertificateUtility
{
  public class CrlBuilder
  {
    private X509V2CrlGenerator crlGenerator;

    private readonly string signatureAlgorithm;

    private SecureRandom secureRandom;

    /// <summary>
    /// Initialise Certificate revocation list builder with the default signature algorithm
    /// </summary>
    public CrlBuilder()
    {
      signatureAlgorithm = DefaultCertificateParameters.SignatureAlgorithm;
      Init();
    }

    /// <summary>
    /// Initialise certifcate revocation list builder with provided signature algorithm
    /// </summary>
    /// <param name="signatureAlgorithm"></param>
    public CrlBuilder(string signatureAlgorithm)
    {
      this.signatureAlgorithm = signatureAlgorithm;
      Init();
    }

    private void Init()
    {
      crlGenerator = new X509V2CrlGenerator();
      secureRandom = new SecureRandom(new VmpcRandomGenerator());
    }

    /// <summary>
    /// Adds the issuer of this Crl's common name to the build chain.
    /// </summary>
    /// <param name="issuerName"></param>
    /// <returns></returns>
    public CrlBuilder AddIssuerName(string issuerName)
    {
      crlGenerator.SetIssuerDN(new X509Name(Helper.StringToCNString(issuerName)));
      return this;
    }

    /// <summary>
    /// Add update period for the crl to a default of 1 year.
    /// </summary>
    /// <returns></returns>
    public CrlBuilder AddUpdatePeriod()
    {
      return AddUpdatePeriod(DateTime.Now.AddDays(-1), DateTime.Now.AddYears(1));
    }

    /// <summary>
    /// Add update period for the crl to the custom amount of time provided as parameters.
    /// </summary>
    /// <param name="validFrom"></param>
    /// <param name="validTo"></param>
    /// <returns></returns>
    public CrlBuilder AddUpdatePeriod(DateTime validFrom, DateTime validTo)
    {
      crlGenerator.SetThisUpdate(validFrom);
      crlGenerator.SetNextUpdate(validTo);
      return this;
    }

    /// <summary>
    /// Add the authority key identifier information for the CRL so the crl can be linked to its issuer.
    /// </summary>
    /// <param name="issuingCA">The Certificate of the CA issuing this cert.</param>
    /// <returns></returns>
    public CrlBuilder AddAKID(X509Certificate issuingCA)
    {
      crlGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(issuingCA));
      return this;
    }

    /// <summary>
    /// Creates a crl based on the build chain constructed.
    /// </summary>
    /// <param name="issuerPrivateKey"></param>
    /// <returns></returns>
    public X509Crl Generate(AsymmetricKeyParameter issuerPrivateKey)
    {
      return crlGenerator.Generate(new Asn1SignatureFactory(signatureAlgorithm, issuerPrivateKey, secureRandom));
    }
  }
}
