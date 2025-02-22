using System.Text.Json.Serialization;

namespace AuthServer.Contracts.Auth.Response;

public class FacebookTokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }
}