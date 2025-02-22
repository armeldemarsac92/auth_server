using System.Text.Json.Serialization;

namespace AuthServer.Contracts.Auth.Request;

public class Setup2FaRequest
{
    [JsonPropertyName("phone_number" )]
    public string? PhoneNumber { get; set; }  // Only needed for SMS
}