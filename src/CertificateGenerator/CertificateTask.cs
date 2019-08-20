using CertificateUtility;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Security.Certificates;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace CertificateGenerator
{
  internal class CertificateTask : BaseCertificateTask<CertGen>
  {
    public CertificateTask(CertGen opts, IConfiguration configuration) : base(opts, configuration)
    {

    }

    protected override int Run()
    {
      if (string.IsNullOrEmpty(Options.IssuerName))
      {
        throw new ArgumentException("Issuer name cannot be empty if you are generating a certificate.", nameof(Options.CommonName));
      }
      
      return RunInternal(Options.CommonName, Options.IssuerName);
    }

    private int RunInternal(string subjectName, string issuerName)
    {
      // Builder path for normal certificate.
      var storeCertificate = LoadCACertificate(Options.IssuerName);
      var builder = new CertificateBuilder(Options.KeyStrength, Options.SignatureAlgorithm);
    
      if (!ValidateIssuer(storeCertificate))
      {
        throw new CertificateException(
          "Provided certificate is not a valid CA and therefore cannot issue other certificates.");
      }

      var issuingKeyPair = DotNetUtilities.GetKeyPair(storeCertificate.PrivateKey);
      string[] dpUrls = MenuInterupts.GetCrlDistributionPoints();

      var bcCertificate = builder
        .AddSKID()
        .AddSerialNumber()
        .AddValidityTime()
        .AddExtendedKeyUsages()
        .AddSubjectCommonName(Options.CommonName)
        .AddIssuerCommonName(Options.IssuerName) // Generate from CA.
        .AddBasicConstraints()
        .AddAKID(issuingKeyPair.Public)
        .AddCRLDistributionPoints(dpUrls)
        .Generate(issuingKeyPair.Private, out AsymmetricCipherKeyPair generatedKeyPair);

      var convertedCertificate = GetWindowsCertFromGenerated(bcCertificate, Options.CommonName, generatedKeyPair.Private, builder.SecureRandom);

      if (!string.IsNullOrEmpty(Options.ExportLocation))
      {
        File.WriteAllBytes(Path.Combine(Options.ExportLocation, $"{Options.CommonName}.pfx"),
          convertedCertificate.Export(X509ContentType.Pkcs12));
      }
      else
      {
        // Add CA certificate to Root store
        var machineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        machineStore.Open(OpenFlags.ReadWrite);
        machineStore.Add(convertedCertificate);
        machineStore.Close();
      }

      return SUCCESS;
    }
  }
}
