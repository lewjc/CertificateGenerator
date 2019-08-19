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

    public CrlBuilder()
    {
      signatureAlgorithm = DefaultCertificateParameters.SignatureAlgorithm;
      Init();
    }

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

    public CrlBuilder AddIssuerName(string issuerName)
    {
      crlGenerator.SetIssuerDN(new X509Name(Helper.StringToCNString(issuerName)));
      return this;
    }

    public CrlBuilder AddUpdatePeriod()
    {
      crlGenerator.SetThisUpdate(DateTime.Now.AddDays(-1));
      crlGenerator.SetNextUpdate(DateTime.Now.AddYears(1));
      return this;
    }

    public CrlBuilder AddUpdatePeriod(DateTime validFrom, DateTime validTo)
    {
      crlGenerator.SetThisUpdate(validFrom);
      crlGenerator.SetNextUpdate(validTo);
      return this;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="issuingCA">The Certificate of the CA issuing this cert.</param>
    /// <returns></returns>
    public CrlBuilder AddAKID(X509Certificate issuingCA)
    {
      crlGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(issuingCA));
      return this;
    }

    public X509Crl Generate(AsymmetricKeyParameter issuerPrivateKey)
    {
      return crlGenerator.Generate(new Asn1SignatureFactory(signatureAlgorithm, issuerPrivateKey, secureRandom));
    }
  }
}
