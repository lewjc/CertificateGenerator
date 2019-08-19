using System;
using System.Collections.Generic;

namespace IsaCertificateGenerator
{
  public class MenuInterupts
  {
    public bool GetCrlChoice()
    {
      bool? choice = null;
      while (choice == null)
      {
        Console.WriteLine("Would you like to generate a CRL for this CA? [y]/[n]: ");
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
            Console.WriteLine("Invalid");
            break;
        }
      }

      return choice.Value;
    }

    public string[] GetCrlDistributionPoints()
    {
      var dps = new List<string>();
      Console.WriteLine("Please provide atleast one URL for your certificate revocation lists. Press [X] when done.");
      while (true)
      {
        string response = Console.ReadLine().ToLower();

        if (response.Equals('x') && dps.Count > 0)
        {
          return dps.ToArray();
        }
        else
        {
          bool validUrl = Uri.TryCreate(response, UriKind.Absolute, out Uri url) && url.Scheme == Uri.UriSchemeHttp ||
                          url.Scheme == Uri.UriSchemeHttps;
          if (!validUrl)
          {
            Console.WriteLine("Invalid Url.");
            continue;
          }

          Console.WriteLine("Valid Url added.");
          dps.Add(validUrl.ToString());
        }
      }
    }
  }
}
