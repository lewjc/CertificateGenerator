using CertificateUtility;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace IsaCertificateGenerator.CertificateUtility
{
  internal class CATask : CertificateTask<CAGen>
  {
    public CATask(CAGen opts, IConfiguration configuration) : base(opts, configuration)
    {
    }

    protected override int Run()
    {
      return InternalRun();
    }

    private int InternalRun()
    {
      bool isRoot = string.IsNullOrEmpty(Options.IssuerName);
      var builder = new CertificateBuilder(Options.KeyStrength, Options.SignatureAlgorithm);
      X509Certificate bcCertificate;
      AsymmetricKeyParameter issuingPrivateKey;
      X509Certificate2 storeCertificate = null;

      // Root self signed certificate.
      if (isRoot)
      {
        // Builder path for Root CA
        bcCertificate = builder
          .AddSerialNumber()
          .AddValidityTime()
          .AddExtendedKeyUsages()
          .AddSubjectCommonName(Options.CommonName)
          .AddIssuerCommonName(Options.CommonName) // Self Signed
          .SetCA()
          .GenerateRootWithPrivateKey(out issuingPrivateKey);
      }
      else
      {
        // Builder path for Intermediate CA
        storeCertificate = LoadCACertificate(Options.IssuerName);

        if (!ValidateIssuer(storeCertificate))
        {
          throw new CertificateException(
            "Provided certificate is not a valid CA and therefore cannot issue other certificates.");
        }

        issuingPrivateKey = GetKeyPair(storeCertificate.PrivateKey).Private;
        var bouncyCastleCA = SystemToBcCertificate(storeCertificate);
        
        // Gets crl distribution point(s) from the user. Currently these are http locations that the CRL will exist on the network.
        // Without these, certificate will fail standard X509 verification.

        string[] dpUrls = MenuInterupts.GetCrlDistributionPoints();

        bcCertificate = builder
          .AddSerialNumber()
          .AddValidityTime()
          .AddExtendedKeyUsages()
          .AddSubjectCommonName(Options.CommonName)
          .AddIssuerCommonName(Options.CommonName) // Generate from CA.
          .SetCA()
          .AddCRLDistributionPoints(dpUrls)
          .Generate(issuingPrivateKey);
      }

      var convertedCertificate = GetWindowsCertFromGenerated(bcCertificate,
        bcCertificate.SubjectDN.ToString(), issuingPrivateKey, new SecureRandom());

      if (!string.IsNullOrEmpty(Options.ExportLocation))
      {
        var exportPath =
          Path.Combine($"{Options.ExportLocation}", $"{Helper.StringToCNString(Options.CommonName)}.pfx");
        File.WriteAllBytes(exportPath, convertedCertificate.Export(X509ContentType.Pkcs12));
      }
      else
      {
        // Add CA certificate to Root store
        var machineStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        machineStore.Open(OpenFlags.ReadWrite);

        machineStore.Add(convertedCertificate);

        machineStore.Close();
      }

      bool generateCrl = MenuInterupts.GetCrlChoice();

      if (generateCrl)
      {
        var crlBuilder = new CrlBuilder();
        var crl = crlBuilder
          .AddIssuerName(isRoot ? Options.CommonName : Options.IssuerName)
          .AddUpdatePeriod()
          .AddAKID(isRoot ? bcCertificate : SystemToBcCertificate(storeCertificate))
          .Generate(issuingPrivateKey);

        var exportPath = Path.Join(Configuration["certificateSettings:crlExportPath"],
          $@"{Options.CommonName}_CRL.crl");
        File.WriteAllBytes(exportPath, crl.GetEncoded());
      }

      return SUCCESS;
    }
  }
}
