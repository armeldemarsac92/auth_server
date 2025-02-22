namespace AuthServer.Contracts.Config;

public class AuthConfiguration
{
    public required string CorsAllowOrigin { get; init; }
    public required string JwtIssuer { get; init; }
    public required string JwtAudience { get; init; }
    public required string PrivateKey { get; init; }
    public required string PublicKey { get; init; }
    public required string SourceEmail { get; init; }
    public required string SmtpUsername { get; init; }
    public required string SmtpPassword { get; init; }
    public required List<IdentityProvider> IdentityProviders { get; init; }
}

public class IdentityProvider
{
    public required string Name { get; init; }
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public required string RedirectUri { get; init; }
    public required string Scope { get; init; }
    public required string GrantType { get; init; }
    public required string ResponseType { get; init; }
    public string? CodeEndpoint { get; init; }
    public required string TokenEndpoint { get; init; }
    public required string UserInfoEndpoint { get; init; }
    public required UserClaims UserClaims { get; init; }
    public required string FrontEndRedirectUri { get; set; }
}

public class UserClaims
{
    public required string sub { get; init; }
    public required string email { get; init; }
    public required string name { get; init; }
    public required string given_name { get; init; }
    public required string family_name { get; init; }
    public required string picture { get; init; }
}