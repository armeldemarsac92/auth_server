using System.Text.Json.Serialization;

namespace AuthServer.Contracts.Auth.Request;

public class RegisterUserRequest
{
    [JsonPropertyName("email" )]
    public required string Email { get; set; }
}