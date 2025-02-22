namespace AuthServer.Contracts.Config;

public class QueueConfiguration
{
  public required string Host { get; set; }
  public required int Port { get; set; }
  public required string User { get; set; }
  public required string Password { get; set; }
  public required string ItemsToUpdateQueueName { get; set; }
  public required string ItemsToInsertQueueName { get; set; }
  public required string AiFetcherQueueName { get; set; }
  public required string DefaultUser { get; set; }
  public required string DefaultPass { get; set; }
}