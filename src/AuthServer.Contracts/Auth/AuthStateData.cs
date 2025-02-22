namespace AuthServer.Contracts.Auth;

public class AuthStateData
{
    public required AuthenticationParameters AuthenticationParameters { get; init; }
    public required DateTime Timestamp { get; init; }
    // public bool Used { get; set; }
    // public string ClientIp { get; set; }
    // public string UserAgent { get; set; }
    
    //si on veut sécuriser davantage on peut capturer des informations d'authentification utilisateurs et les valider ensuite'
}