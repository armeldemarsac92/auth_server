namespace AuthServer.Contracts.Config;

public class ProxyConfiguration
{
  public required string SslCertPfx { get; set; }
  public required string SslCert { get; set; }
  public required string SslCertKey { get; set; }
}