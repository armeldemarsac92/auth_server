namespace AuthServer.Contracts.Config;

public class NetworkConfiguration
{
  public required string SeeqrApiHost { get; set; }
  public required string VintedApiHost { get; set; }
  public required string VintedDomain { get; set; }
  public required string ProxyHost { get; set; }
}