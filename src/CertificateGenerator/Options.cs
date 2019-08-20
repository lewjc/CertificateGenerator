using CommandLine;

namespace CertificateGenerator
{
  internal class CLOptions
  {
    [Option('e', "exportdir", HelpText = "Specifies a location to export a certificate. If this is blank, a certificate will not be exported but installed.")]
    public string ExportLocation { get; set; }

    [Option('c', "commonname", HelpText = "The common name for the certificate. If used with CRL generation, will name the crl this.", Required = true)]
    public string CommonName { get; set; }

    [Option('k', "keystrength", HelpText = "The Keystrength of the certificate. Default is 2048.", Default = 2048)]
    public int KeyStrength { get; set; }

    [Option('a', "algorithm", HelpText = "The signature algorithm used for sigining the certificate", Default = "SHA256WithRSA")]
    public string SignatureAlgorithm { get; set; }
  }

  [Verb("Cert", HelpText = "Generates a certificate")]
  internal class CertGen : CLOptions
  {
    [Option('i', "issuer", HelpText = "The common name of the issuing Certificate Authority", Required = true)]
    public string IssuerName { get; set; }
  }

  [Verb("CA", HelpText = "Generate a root or intermediate certificate authority")]
  internal class CAGen : CLOptions
  {
    [Option('p', "parentCA", HelpText = "The common name of the issuing Certificate Authority, if this is empty then a root CA will be created. ")]
    public string IssuerName { get; set; }
  }

  [Verb("CRL", HelpText = "Generate a CRL")]
  internal class CRL : CLOptions
  {
    [Option('i', "issuer", HelpText = "The common name of the Certificate Authority that issues this CRL.", Required = true)]
    public string IssuerName { get; set; }
  }
}
