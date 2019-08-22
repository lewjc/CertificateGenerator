using CertificateUtility;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security.Certificates;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using NLog;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace CertificateGenerator
{
  internal class CATask : BaseCertificateTask<CAOptions>
  {
    public CATask(CAOptions opts, IConfiguration configuration, LogFactory logFactory) : base(opts, configuration, logFactory)
    {
    }

    protected override int Run()
    { 
      return InternalRun();
    }

    private int InternalRun()
    {
      bool isRoot = string.IsNullOrEmpty(Options.IssuerName);
      var builder = new CertificateBuilder(Options.KeyStrength, Options.SignatureAlgorithm, Logger);
      X509Certificate bcCertificate;
      // Key pair of the issuing certificate.
      AsymmetricCipherKeyPair issuingKeyPair = null;
      // Key pair for the generated certificate.
      AsymmetricCipherKeyPair generatedKeyPair = null;
      X509Certificate2 storeCertificate = null;

      // Root self signed certificate.
      if (isRoot)
      {
        // Builder path for Root CA
        bcCertificate = builder
          .AddSKID()
          .AddSerialNumber()
          .AddValidityTime()
          .AddExtendedKeyUsages()
          .AddSubjectCommonName(Options.CommonName)
          .AddIssuerCommonName(Options.CommonName) // Self Signed
          .MakeCA()
          .GenerateRootWithPrivateKey(out issuingKeyPair);
      }
      else
      {
        storeCertificate = LoadCACertificate(Options.IssuerName);
        builder = new CertificateBuilder(Options.KeyStrength, Options.SignatureAlgorithm, Logger);

        if (!ValidateIssuer(storeCertificate))
        {
          throw new CertificateException(
            "Provided certificate is not a valid CA and therefore cannot issue other certificates.");
        }

        issuingKeyPair = DotNetUtilities.GetKeyPair(storeCertificate.PrivateKey);

        string[] dpUrls = Options.DistributionPoints.Count() > 0 ? Options.DistributionPoints.ToArray(): MenuInterupts.GetCrlDistributionPoints();

        bcCertificate = builder
          .AddSKID()
          .AddSerialNumber()
          .AddValidityTime()
          .AddExtendedKeyUsages()
          .AddSubjectCommonName(Options.CommonName)
          .AddIssuerCommonName(Options.IssuerName) // Generate from CA.
          .AddAKID(issuingKeyPair.Public)
          .AddCRLDistributionPoints(dpUrls)
          .MakeCA()
          .Generate(issuingKeyPair.Private, out generatedKeyPair);
      }

      var convertedCertificate = GetWindowsCertFromGenerated(bcCertificate,
        Options.CommonName, isRoot ? issuingKeyPair.Private : generatedKeyPair.Private, builder.SecureRandom);

      if (Options.Debug)
      {
        DisplayCertificateDebugInfo(convertedCertificate);
      }

      if (!string.IsNullOrEmpty(Options.ExportLocation))
      {
        // Export the certificate to the 
        var exportPath =
          Path.Combine($"{Options.ExportLocation}", $"{Helper.StringToCNString(Options.CommonName)}.pfx");
        File.WriteAllBytes(exportPath, convertedCertificate.Export(X509ContentType.Pkcs12));
      }
      else
      {
        // Add CA certificate to Root store
        var machineStore = new X509Store(isRoot ? StoreName.Root : StoreName.CertificateAuthority, StoreLocation.LocalMachine);
        machineStore.Open(OpenFlags.ReadWrite);

        machineStore.Add(convertedCertificate);

        machineStore.Close();
      }

      // Get our crl choice for this certificate authority.
      bool generateCrl = Options.GenerateCRL ? Options.GenerateCRL : MenuInterupts.GetCrlChoice();

      if (generateCrl)
      {
        var crlKeyPair = isRoot ? issuingKeyPair : generatedKeyPair;

        var crlBuilder = new CrlBuilder();
        var crl = crlBuilder
          .AddIssuerName(Options.CommonName)
          .AddUpdatePeriod()
          .AddAKID(crlKeyPair.Public)
          .Generate(crlKeyPair.Private);

        var crlPostFix = Configuration["certificateSettings:crlPostFix"];
        var exportPath = Path.Join(Configuration["certificateSettings:crlExportPath"],
          $"{Options.CommonName}{crlPostFix}.crl");
        File.WriteAllBytes(exportPath, crl.GetEncoded());
        Logger.Info($"CRL Generated at {exportPath}");
      }

      return SUCCESS;
    }
  }
}
