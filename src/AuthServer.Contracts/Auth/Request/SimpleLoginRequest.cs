using System.Text.Json.Serialization;

namespace AuthServer.Contracts.Auth.Request;

public class SimpleLoginRequest
{
    [JsonPropertyName("email" )]
    public required string Email { get; set; } 
    
    [JsonPropertyName("two_factor_code")]
    public string? TwoFactorCode { get; set; }
}