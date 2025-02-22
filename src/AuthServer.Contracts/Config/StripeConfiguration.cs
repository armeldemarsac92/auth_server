namespace AuthServer.Contracts.Config;

public class StripeConfiguration
{
  public required string ApiKey { get; set; }
  public required string PaymentWebhookSecret { get; set; }
}