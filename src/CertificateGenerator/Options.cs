using CommandLine;
using CommandLine.Text;

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

    [Option("debug", HelpText = "Whether or not to display debug information.", Default = false)]
    public bool Debug { get; set; }
  }

  internal class GenericCertificateOptions : CLOptions
  {

    [Option('d', "distributionpoints", HelpText = "(Provide with Non root Certificate) An array of HTTP URIs that point to crl locations on the network\n" +
                                                  "NOTE: If none are provided, an interactive window will display asking for input")]
    public string[] DistributionPoints { get; set; }

    [Option('i', "issuer", HelpText = "The common name of the issuer that will be signing this certificate.", Required = true)]
    public virtual string IssuerName { get; set; }
  }


  [Verb("Cert", HelpText = "Generates a leaf certificate, capable of being used for encryption, token signing and verification.\n" +
                           "Examples:\n" +
                           "[--commonname JWTSigningLeaf --issuer InternalRootCA --keystrength 2048 --algorithm SHA512WithRSA]\n" +
                           "These parameters would generate a certificate with the commonname CN=JWTSigningLeaf, signed by the InternalRootCA.\n" +
                           "This CA would have to exist on your machine to sign it.")]
  internal class CertificateOptions : GenericCertificateOptions
  {

  }

  [Verb("CA", HelpText = "Generate a root or intermediate certificate authority on the executing machine.\n" +
                         "Examples:\n" +
                         "[--commonname InternalRootCA]\n" +
                         "This parameter set would generate a root CA 0with the commonname CN=InternalRootCA, signed by itself.\n" +
                         "[--commonname IntermediateNetworkCA --parentCA InternalRootCA --exportdir C:\\Desktop ]\n" +
                         "This parameter set would create an intermediate CA signed by a certificate with the common name of InternalRootCA.\n" +
                         "It would be exported with the private key to the desktop location on the C drive (If this existed)" +
                         "")]
  internal class CAOptions : GenericCertificateOptions
  {
    [Option('p', "parentCA", HelpText = "The common name of the issuing Certificate Authority, if this is empty then a root CA will be created. ")]
    public override string IssuerName { get; set; }

    [Option('g', "generateCRL", HelpText = "Whether or not to generate a CRL with this CA.", Default = false)]
    public bool GenerateCRL { get; set; }
  }

  [Verb("CRL", HelpText = "Generate a CRL")]
  internal class CrlOptions : CLOptions
  {
    [Option('i', "issuer", HelpText = "The common name of the Certificate Authority that issues this CRL.", Required = true)]
    public string IssuerName { get; set; }
  }
}
