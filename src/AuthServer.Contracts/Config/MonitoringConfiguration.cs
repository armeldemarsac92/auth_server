namespace AuthServer.Contracts.Config;

public class MonitoringConfiguration
{
  public required string GrafanaAdminUser { get; set; }
  public required string GrafanaAdminPassword { get; set; }
}