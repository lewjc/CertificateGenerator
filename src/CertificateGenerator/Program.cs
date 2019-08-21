using System;
using CommandLine;
using Microsoft.Extensions.Configuration;
using System.IO;
using NLog;
using System.Reflection;
using NLog.Config;

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

      Parser.Default.ParseArguments<CertificateOptions, CAOptions, CrlOptions>(args).MapResult(
        (CertificateOptions options) =>
        {
          var logger = GetLogFactory(options);
          return new CertificateTask(options, configuration, logger).Execute();
        },
        (CAOptions options) =>
        {
          var logger = GetLogFactory(options);
          return new CATask(options, configuration, logger).Execute();
        }, 
        (CrlOptions options) =>
        {
          var logger = GetLogFactory(options);
          return new CrlTask(options, configuration, logger).Execute();
        }, errs => 1);
    }

    private static LogFactory GetLogFactory(CLOptions options)
    {
      var loadFolder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

      var configFile = Path.Combine(loadFolder, "NLog.config");

      var logConfig = new XmlLoggingConfiguration(configFile);

      foreach (var rule in logConfig.LoggingRules)
      {
        rule.SetLoggingLevels(options.Debug ? LogLevel.Debug : LogLevel.Info, LogLevel.Fatal);
      }

      return new LogFactory(logConfig);
    }
  }
}
