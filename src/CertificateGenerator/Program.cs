using CommandLine;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace CertificateGenerator
{
  public class Program
  {
    public static void Main(string[] args)
    {
      var configuration = new ConfigurationBuilder()
        .SetBasePath(Directory.GetCurrentDirectory())
        .AddJsonFile("appsettings.json", optional: true,
          reloadOnChange: true).Build();

      Parser.Default.ParseArguments<CertGen, CAGen>(args).MapResult(
        (CertGen options) =>
        {
          return new CertificateTask(options, configuration).Execute();
        },
        (CAGen options) =>
        {
          return new CATask(options, configuration).Execute();
        },
        errs => 1);
    }
  }
}
