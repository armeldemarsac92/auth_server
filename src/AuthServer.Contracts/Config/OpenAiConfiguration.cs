namespace AuthServer.Contracts.Config;

public class OpenAiConfiguration
{
  public required string ApiKey { get; set; }
  public required string OrganizationId { get; set; }
  public required string ProjectId { get; set; }
  public required string BrandAssistantId { get; set; }
  public required string ItemAssistantId { get; set; }
  public required string ItemSizesAssistantId { get; set; }
  public required string EmbeddingModelName { get; set; }
  public required string Model { get; set; }
}