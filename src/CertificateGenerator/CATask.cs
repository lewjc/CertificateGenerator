using CertificateUtility;
using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace CertificateGenerator
{
  internal class CATask : BaseCertificateTask<CAGen>
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
      AsymmetricCipherKeyPair issuingKeyPair = null;
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
        builder = new CertificateBuilder(Options.KeyStrength, Options.SignatureAlgorithm);

        if (!ValidateIssuer(storeCertificate))
        {
          throw new CertificateException(
            "Provided certificate is not a valid CA and therefore cannot issue other certificates.");
        }

        issuingKeyPair = DotNetUtilities.GetKeyPair(storeCertificate.PrivateKey); ;

        string[] dpUrls = MenuInterupts.GetCrlDistributionPoints();

        bcCertificate = builder
          .AddSKID()
          .AddSerialNumber()
          .AddValidityTime()
          .AddExtendedKeyUsages()
          .AddSubjectCommonName(Options.CommonName)
          .AddIssuerCommonName(Options.IssuerName) // Generate from CA.
          .MakeCA()
          .AddAKID(issuingKeyPair.Public)
          .AddCRLDistributionPoints(dpUrls)
          .Generate(issuingKeyPair.Private, out generatedKeyPair);
      }

      var convertedCertificate = GetWindowsCertFromGenerated(bcCertificate,
        Options.CommonName, isRoot ? issuingKeyPair.Private : generatedKeyPair.Private, builder.SecureRandom);

      if (!string.IsNullOrEmpty(Options.ExportLocation))
      {
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

      bool generateCrl = MenuInterupts.GetCrlChoice();

      if (generateCrl)
      {
        var crlBuilder = new CrlBuilder();
        var crl = crlBuilder
          .AddIssuerName(isRoot ? Options.CommonName : Options.IssuerName)
          .AddUpdatePeriod()
          .AddAKID(issuingKeyPair.Public)
          .Generate(issuingKeyPair.Private);

        var crlPostFix = Configuration["certificateSettings:crlPostFix"];
        var exportPath = Path.Join(Configuration["certificateSettings:crlExportPath"],
          $"{Options.CommonName}{crlPostFix}.crl");
        File.WriteAllBytes(exportPath, crl.GetEncoded());
      }

      return SUCCESS;
    }
  }
}
