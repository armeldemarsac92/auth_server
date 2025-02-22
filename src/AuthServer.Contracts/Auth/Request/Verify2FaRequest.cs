using System.Text.Json.Serialization;

namespace AuthServer.Contracts.Auth.Request;

public class Verify2FaRequest
{
    [JsonPropertyName("verification_code" )]
    public required string VerificationCode { get; set; } 
}