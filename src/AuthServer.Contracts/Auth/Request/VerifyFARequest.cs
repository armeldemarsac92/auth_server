using System.Text.Json.Serialization;

namespace AuthServer.Contracts.Auth.Request;

public class VerifyFaRequest
{
    [JsonPropertyName("verification_code" )]
    public required string VerificationCode { get; set; }  
    
    [JsonPropertyName("email")]
    public required string Email { get; set; }
}