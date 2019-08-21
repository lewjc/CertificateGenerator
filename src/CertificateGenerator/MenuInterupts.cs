using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using NLog;

namespace CertificateGenerator
{
  internal class MenuInterupts
  {

    private readonly ILogger logger;

    internal MenuInterupts(ILogger logger)
    {

    }

    public bool GetCrlChoice()
    {
      bool? choice = null;
      while (choice == null)
      {
        logger.Info("Would you like to generate a CRL for this CA? [y]/[n]: ");
        string response = Console.ReadLine().ToLower();

        switch (response)
        {
          case "y":
            choice = true;
            break;

          case "n":
            choice = false;
            break;

          default:
            logger.Error("Invalid Choice");
            break;
        }
      }

      return choice.Value;
    }

    public string[] GetCrlDistributionPoints()
    {
      var dps = new List<string>();
      logger.Info("Please provide atleast one URL for your certificate revocation lists. Press [X] when done.");
      while (true)
      {
        string response = Console.ReadLine().ToLower();

        if (response.Equals("x") && dps.Count > 0)
        {
          return dps.ToArray();
        }
        else
        {
          bool validUrl = Uri.TryCreate(response, UriKind.Absolute, out Uri url) && url.Scheme == Uri.UriSchemeHttp ||
                          url.Scheme == Uri.UriSchemeHttps;
          if (!validUrl)
          {
            logger.Error("Invalid Url.");
            continue;
          }

          logger.Info($"Valid Url added => {url.AbsoluteUri}");
          dps.Add(url.AbsoluteUri);
        }
      }
    }
  }
}
