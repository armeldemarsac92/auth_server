using System.Security.Cryptography;
using System.Text;

namespace AuthServer.Contracts.Auth;

public class AuthenticationParameters
{
    protected AuthenticationParameters() { }

    public AuthenticationParameters(string identityProvider)
    {
        IdentityProvider = identityProvider;
        State = GenerateSecureToken();
        ChallengeVerifier = GenerateSecureToken();
        Challenge = CreateCodeChallenge(ChallengeVerifier);
    }

    public string IdentityProvider { get; init; }
    public string? AuthorizationCode { get; set; }
    public string? AccessToken { get; set; }
    public string State { get; init; }
    public string Challenge { get; init; }
    public string ChallengeVerifier { get; init; }
    public string FrontEndRedirectUri { get; set; }
    
    private string GenerateSecureToken()
    {
        var bytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        return Base64UrlEncode(bytes);
    }
    private string CreateCodeChallenge(string codeVerifier)
    {
        using (var sha256 = SHA256.Create())
        {
            var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            return Base64UrlEncode(challengeBytes);
        }
    }

    private string Base64UrlEncode(byte[] input)
    {
        var base64 = Convert.ToBase64String(input);
        return base64
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}

public enum AuthenticationFlowType { AuthorizationCode, Implicit }
