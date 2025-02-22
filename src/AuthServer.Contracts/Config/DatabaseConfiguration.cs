namespace AuthServer.Contracts.Config;

public class DatabaseConfiguration
{
  public required string Key { get; set; }
  public required string Url { get; set; }
  public required string Email { get; set; }
  public required string Password { get; set; }
  public required string DbConnectionString { get; set; }
  public required string SslCert { get; set; }
}