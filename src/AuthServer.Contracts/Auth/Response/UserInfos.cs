using System.Text.Json.Serialization;

namespace AuthServer.Contracts.Auth.Response;

public class UserInfos
{
    [JsonPropertyName("sub")]
    public string Sub { get; set; }
    
    [JsonPropertyName("email")]
    public string Email { get; set; }
    
    [JsonPropertyName("given_name")]
    public string GivenName { get; set; }
    
    [JsonPropertyName("family_name")]
    public string FamilyName { get; set; }    
    
    [JsonPropertyName("picture")]
    public string Picture { get; set; }
}