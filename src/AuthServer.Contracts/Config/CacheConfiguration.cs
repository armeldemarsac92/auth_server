namespace AuthServer.Contracts.Config;

public class CacheConfiguration
{
    public required string Host { get; set; }
    public required string InstanceName { get; set; }
    public required string KeyPrefix { get; set; }
}