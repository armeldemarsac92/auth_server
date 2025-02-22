using System.Text.Json.Serialization;

namespace AuthServer.Contracts.Auth.Request;

public class ResendConfirmationRequest
{
    [JsonPropertyName("email" )]
    public required string Email { get; set; }
}