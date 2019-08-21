using CertificateUtility;
using Microsoft.Extensions.Configuration;
using NLog;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using NLog.Fluent;

namespace CertificateGenerator
{
  internal abstract class BaseCertificateTask<TOptions> where TOptions : CLOptions
  {
    private const string STOREPASSWORD = "98DSFvc3fn393Jxxs";

    protected readonly int FAIL = 0;

    protected readonly int SUCCESS = 1;

    protected TOptions Options { get; }

    protected ILogger Logger { get; set; }

    protected IConfiguration Configuration { get; set; }

    protected MenuInterupts MenuInterupts { get; set; }

    protected BaseCertificateTask(TOptions opts, IConfiguration configuration, LogFactory logFactory)
    {
      Options = opts;
      Configuration = configuration;
      Logger = logFactory.GetLogger(GetType().Name);
      MenuInterupts = new MenuInterupts(Logger);
    }

    public int Execute()
    {
      try
      {
        if (string.IsNullOrEmpty(Options.CommonName))
        {
          throw new ArgumentNullException(nameof(Options.CommonName), "Common name must be specified.");
        }

        if (Options.ExportLocation != null && !Directory.Exists(Options.ExportLocation))
        {
          throw new ArgumentException("Directory is invalid", nameof(Options.ExportLocation));
        }

        return Run();
      }
      catch (Exception e)
      {
        Logger.Info(e.Message);
        return FAIL;
      }
      finally
      {
        Logger.Info("[ANY KEY TO EXIT]");
        Console.ReadLine();
      }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    protected abstract int Run();

    /// <summary>
    /// 
    /// </summary>
    /// <param name="issuerCN"></param>
    /// <returns></returns>
    protected X509Certificate2 LoadCACertificate(string issuerCN)
    {
      IEnumerable<X509Store> stores = new X509Store[] { new X509Store(StoreName.Root, StoreLocation.LocalMachine),
        new X509Store(StoreName.CertificateAuthority, StoreLocation.LocalMachine)};

      List<X509Certificate2> foundCertificates = new List<X509Certificate2>();

      foreach (var store in stores)
      {
        store.Open(OpenFlags.ReadOnly);
        var results = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName,
          Helper.StringToCNString(issuerCN), true);
        if (results.Count == 0)
        {
          continue;
        }
        else
        {
          foundCertificates.AddRange(results.Cast<X509Certificate2>());
        }

        store.Close();
      }

      if (foundCertificates.Count == 0)
      {
        throw new ArgumentException("Provided issuer does not exist in the Root or Intermediate certificate store on this machine.");
      }
      else if (foundCertificates.Count == 1)
      {
        return foundCertificates.First();
      }
      else
      {
        // Multiple certificates.
        // TODO: Deal with multiple certificates with the same common name.
        return foundCertificates.First();
      }

    }

    /// <summary>
    /// Gets the .NET certificate from the bouncy castle certificate.
    /// </summary>
    /// <param name="cert">The certificate.</param>
    /// <param name="friendlyName">The friendly name.</param>
    /// <param name="keyPair">The key pair.</param>
    /// <param name="random">A random number generator.</param>
    /// <returns></returns>
    protected X509Certificate2 GetWindowsCertFromGenerated(Org.BouncyCastle.X509.X509Certificate cert,
      string friendlyName, AsymmetricKeyParameter privateKey, SecureRandom random)
    {
      // Create a PKS store.
      var store = new Pkcs12Store();

      // Generate a cert entry
      var certificateEntry = new X509CertificateEntry(cert);

      // Add it into the in-memory store.
      store.SetCertificateEntry(friendlyName, certificateEntry);

      // Add the key.
      store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(privateKey), new[] { certificateEntry });

      var stream = new MemoryStream();

      // Save the store to a stream..
      store.Save(stream, STOREPASSWORD.ToCharArray(), random);

      // Now load that same certificate.
      var convertedCertificate =
        new X509Certificate2(
          stream.ToArray(), STOREPASSWORD,
          X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

      return convertedCertificate;
    }

    /// <summary>
    /// Validates the provieded issuer certifcate object to ensure it is a valid certificate authority.
    /// </summary>
    /// <param name="issuerCertificate"></param>
    /// <returns></returns>
    protected bool ValidateIssuer(X509Certificate2 issuerCertificate)
    {
      foreach (var extension in issuerCertificate.Extensions)
      {
        if (extension.Oid.FriendlyName.Equals(ExtensionFriendlyNames.KeyUsage, StringComparison.CurrentCultureIgnoreCase))
        {
          var ext = (X509KeyUsageExtension)extension;
          if (issuerCertificate.Version < 3)
          {
            continue;
          }

          if ((!ext.KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign) || !ext.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign) && ext.KeyUsages > 0))
          {
            // If cert does not have either of these flags and has flags, it is not a valid CA.
            return false;
          }
        }

        if (extension.Oid.FriendlyName.Equals(ExtensionFriendlyNames.BasicConstraints, StringComparison.CurrentCultureIgnoreCase))
        {
          var ext = (X509BasicConstraintsExtension)extension;
          if (!ext.CertificateAuthority)
          {
            return false;
          }
        }
      }

      return issuerCertificate.Verify();
    }
  }
}
