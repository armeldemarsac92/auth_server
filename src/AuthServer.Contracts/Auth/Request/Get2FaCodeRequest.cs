using System.Text.Json.Serialization;

namespace AuthServer.Contracts.Auth.Request;

public class Get2FaCodeRequest
{
    [JsonPropertyName("email" )]
    public required string Email { get; set; }
}