using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.Configuration;
using NLog;

namespace CertificateGenerator
{
  internal class CrlTask : BaseCertificateTask<CrlOptions>
  {
    public CrlTask(CrlOptions opts, IConfiguration configuration, LogFactory logger) : base(opts, configuration, logger)
    {
    }

    protected override int Run()
    {
      throw new NotImplementedException();
    }
  }
}
