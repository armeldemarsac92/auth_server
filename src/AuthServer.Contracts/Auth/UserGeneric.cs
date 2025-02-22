using System.Text.Json.Serialization;

namespace AuthServer.Contracts.Auth;

public class UserGeneric
{
    [JsonPropertyName("first_name")] 
    public string FirstName { get; init; }

    [JsonPropertyName("last_name")] 
    public string LastName { get; init; }

    [JsonPropertyName("email")] 
    public string EmailAdress { get; init; }

    [JsonPropertyName("identifiant")] 
    public string Identifiant { get; init; }

    [JsonPropertyName("service")]
    public string? CodeService { get; init; }

    [JsonPropertyName("territoire")]
    public string? CodeTerritoire { get; init; }

    [JsonPropertyName("tel_direct")] 
    public string? TelDirect { get; init; }

    [JsonPropertyName("tel_portable")] 
    public string? TelPortable { get; init; }

    [JsonPropertyName("profile")] 
    public string? CodeProfile { get; init; }
    
    [JsonPropertyName("fonction")] 
    public string? Fonction { get; init; }
    
    [JsonPropertyName("custom1")] 
    public string? Custom1 { get; init; }
    
    [JsonPropertyName("custom2")] 
    public string? Custom2 { get; init; }
    
    [JsonPropertyName("custom3")] 
    public string? Custom3 { get; init; }

}

