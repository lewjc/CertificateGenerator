using CertificateUtility;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Security.Certificates;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

namespace IsaCertificateGenerator
{
  internal class CertificateGenerator : CertificateTask<CertGen>
  {
    public CertificateGenerator(CertGen opts, IConfiguration configuration) : base(opts, configuration)
    {

    }

    protected override int Run()
    {
      if (string.IsNullOrEmpty(Options.IssuerName))
      {
        throw new ArgumentException("Issuer name cannot be empty if you are generating a certificate.", nameof(Options.CommonName));
      }

      GenerateCertificate(Options.CommonName, Options.IssuerName);

      return SUCCESS;
    }

    public int GenerateCertificate(string subjectName, string issuerName)
    {
      // Builder path for Intermediate CA
      var storeCertificate = LoadCACertificate(Options.IssuerName);
      var builder = new CertificateBuilder(Options.KeyStrength, Options.SignatureAlgorithm);

      if (!ValidateIssuer(storeCertificate))
      {
        throw new CertificateException(
          "Provided certificate is not a valid CA and therefore cannot issue other certificates.");
      }

      var issuingPrivateKey = GetKeyPair(storeCertificate.PrivateKey).Private;
      var bouncyCastleCA = SystemToBcCertificate(storeCertificate);

      string[] dpUrls = MenuInterupts.GetCrlDistributionPoints();

      var bcCertificate = builder
        .AddSerialNumber()
        .AddValidityTime()
        .AddExtendedKeyUsages()
        .AddSubjectCommonName(Options.CommonName)
        .AddIssuerCommonName(Options.CommonName) // Generate from CA.
        .SetCA()
        .AddCRLDistributionPoints(dpUrls)
        .Generate(issuingPrivateKey);

      var convertedCertificate = GetWindowsCertFromGenerated(bcCertificate, Options.CommonName, issuingPrivateKey, new SecureRandom(new VmpcRandomGenerator()));

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
