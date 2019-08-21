using CertificateUtility;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Security.Certificates;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using NLog;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;
using System.Linq;

namespace CertificateGenerator
{
  internal class CertificateTask : BaseCertificateTask<CertificateOptions>
  {
    public CertificateTask(CertificateOptions opts, IConfiguration configuration, LogFactory logger) : base(opts, configuration, logger)
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
      var builder = new CertificateBuilder(Options.KeyStrength, Options.SignatureAlgorithm, Logger);
    
      if (!ValidateIssuer(storeCertificate))
      {
        Logger.Error("Provided issuer is not a valid CA and therefore cannot issue other certificates.");
        throw new CertificateException(
          "Provided issuer is not a valid CA and therefore cannot issue other certificates.");
      }

      var issuingKeyPair = DotNetUtilities.GetKeyPair(storeCertificate.PrivateKey);
      string[] dpUrls = Options.DistributionPoints.Count() > 0 ? Options.DistributionPoints.ToArray() : MenuInterupts.GetCrlDistributionPoints();

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

      if (Options.Debug)
      {
        DisplayCertificateDebugInfo(convertedCertificate);
      }

      X509Chain chain = new X509Chain();
      chain.Build(convertedCertificate);

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
