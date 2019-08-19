namespace CertificateUtility
{
  public static class Helper
  {

    /// <summary>
    /// Converts a name into a Common name string.
    /// </summary>
    /// <param name="name"></param>
    /// <returns></returns>
    public static string StringToCNString(string name)
    {
      if (name.Contains("CN="))
      {
        return name;
      }

      return $"CN={name}";
    }
  }
}
