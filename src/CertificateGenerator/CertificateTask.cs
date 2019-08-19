using CertificateUtility;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SystemX509 = System.Security.Cryptography.X509Certificates;

namespace IsaCertificateGenerator
{
  internal abstract class CertificateTask<TOptions> where TOptions : CLOptions
  {
    private const string STOREPASSWORD = "CSI_Ma35tr0";

    protected readonly int FAIL = 0;

    protected readonly int SUCCESS = 1;

    protected TOptions Options { get; }

    protected ILogger Logger { get; set; }

    protected IConfiguration Configuration { get; set; }

    protected MenuInterupts MenuInterupts { get; set; }

    protected CertificateTask(TOptions opts, IConfiguration configuration)
    {
      Options = opts;
      Configuration = configuration;
      MenuInterupts = new MenuInterupts();
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
        Debug.WriteLine(e.Message);
        return FAIL;
      }
    }

    protected abstract int Run();

    protected X509Certificate2 LoadCACertificate(string issuerCN)
    {
      var machineStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
      try
      {
        machineStore.Open(OpenFlags.ReadWrite);

        var certs = machineStore.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, $"CN={issuerCN}", true);

        foreach (var cert in certs)
        {
          return cert;
        }
      }
      finally
      {
        machineStore.Close();
      }

      return null;
    }

    protected AsymmetricCipherKeyPair GetKeyPair(AsymmetricAlgorithm privateKey)
    {
      if (privateKey is DSA)
      {
        return GetDsaKeyPair((DSA)privateKey);
      }

      if (privateKey is RSA)
      {
        return GetRsaKeyPair((RSA)privateKey);
      }

      throw new ArgumentException("Unsupported algorithm specified", "privateKey");
    }

    private AsymmetricCipherKeyPair GetDsaKeyPair(DSA dsa)
    {
      return GetDsaKeyPair(dsa.ExportParameters(true));
    }

    private AsymmetricCipherKeyPair GetDsaKeyPair(DSAParameters dp)
    {
      DsaValidationParameters validationParameters = (dp.Seed != null)
        ? new DsaValidationParameters(dp.Seed, dp.Counter)
        : null;

      DsaParameters parameters = new DsaParameters(
        new BigInteger(1, dp.P),
        new BigInteger(1, dp.Q),
        new BigInteger(1, dp.G),
        validationParameters);

      DsaPublicKeyParameters pubKey = new DsaPublicKeyParameters(
        new BigInteger(1, dp.Y),
        parameters);

      DsaPrivateKeyParameters privKey = new DsaPrivateKeyParameters(
        new BigInteger(1, dp.X),
        parameters);

      return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    private AsymmetricCipherKeyPair GetRsaKeyPair(RSA rsa)
    {
      return GetRsaKeyPair(rsa.ExportParameters(true));
    }

    private AsymmetricCipherKeyPair GetRsaKeyPair(RSAParameters rp)
    {
      BigInteger modulus = new BigInteger(1, rp.Modulus);
      BigInteger pubExp = new BigInteger(1, rp.Exponent);

      RsaKeyParameters pubKey = new RsaKeyParameters(
        false,
        modulus,
        pubExp);

      RsaPrivateCrtKeyParameters privKey = new RsaPrivateCrtKeyParameters(
        modulus,
        pubExp,
        new BigInteger(1, rp.D),
        new BigInteger(1, rp.P),
        new BigInteger(1, rp.Q),
        new BigInteger(1, rp.DP),
        new BigInteger(1, rp.DQ),
        new BigInteger(1, rp.InverseQ));

      return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    protected Org.BouncyCastle.X509.X509Certificate SystemToBcCertificate(SystemX509.X509Certificate certificate)
    {
      return new X509CertificateParser().ReadCertificate(certificate.GetRawCertData());
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
