using CommandLine;
using IsaCertificateGenerator.CertificateUtility;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace IsaCertificateGenerator
{
  internal class Program
  {
    private static void Main(string[] args)
    {
      var configuration = new ConfigurationBuilder()
        .SetBasePath(Directory.GetCurrentDirectory())
        .AddJsonFile("appsettings.json", optional: true,
          reloadOnChange: true).Build();

      Parser.Default.ParseArguments<CertGen, CAGen>(args).MapResult(
        (CertGen options) =>
        {
          return new CertificateGenerator(options, configuration).Execute();
        },
        (CAGen options) =>
        {
          return new CATask(options, configuration).Execute();
        },
        errs => 1);
    }
  }
}
