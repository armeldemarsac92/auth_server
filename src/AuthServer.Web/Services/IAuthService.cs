using System.Net.Http.Headers;
using System.Text.Json;
using AuthServer.Contracts.Auth;
using AuthServer.Contracts.Auth.Response;
using AuthServer.Contracts.Config;
using AuthServer.Contracts.Exceptions;
using AuthServer.Web.Extensions;

namespace AuthServer.Web.Services;

public interface IAuthService
{
    public Task<string> InstantiateOAuthFlow(string provider);
    public Task<AuthenticationParameters> GetAuthenticationParameters(HttpContext context);
    public Task<UserInfos> GetUserInfosAsync(AuthenticationParameters parameters);
}

public class AuthService : IAuthService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly AuthConfiguration _authConfiguration;
    private readonly ISecurityService _securityService;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        IHttpClientFactory httpClientFactory, 
        AuthConfiguration authConfiguration, 
        ILogger<AuthService> logger, 
        ISecurityService securityService)
    {
        _httpClientFactory = httpClientFactory;
        _authConfiguration = authConfiguration;
        _logger = logger;
        _securityService = securityService;
    }

    public async Task<string> InstantiateOAuthFlow(string provider)
    {
        _logger.LogInformation("Instantiating OAuth flow for provider: {provider}", provider);
        var authParameters = new AuthenticationParameters(provider);
        _logger.LogInformation("Storing authentication parameters in memory cache");
        await _securityService.StoreAuthState(authParameters);
        return BuildLoginUri(authParameters);
    }

    public async Task<AuthenticationParameters> GetAuthenticationParameters(HttpContext context)
    {
        _logger.LogInformation("Getting authentication parameters from context, retrieving 'state' parameter");
        var state = context.GetUriParameterFromHttpContext("state");
        var authStateData = await _securityService.ValidateState(state);
        var authParameters = authStateData.AuthenticationParameters;
        _logger.LogInformation("Authentication parameters retrieved successfully");
        
        _logger.LogInformation("Retrieving 'code' parameter");
        var code = context.GetUriParameterFromHttpContext("code");
        authParameters.AuthorizationCode = code;
        var tokenResponse = await ExchangeCodeForTokens(authParameters);
        authParameters.AccessToken = tokenResponse.AccessToken;
        
        return authParameters;
    }
    
    public async Task<UserInfos> GetUserInfosAsync(AuthenticationParameters parameters)
    {
        var idpConfig = _authConfiguration.IdentityProviders.FirstOrDefault(idp => idp.Name == parameters.IdentityProvider);
        if (idpConfig is null) throw new BadRequestException($"Invalid IDP: {parameters.IdentityProvider}");
        
        _logger.LogInformation("Getting user info from {idp}", idpConfig.Name);
        var infosClientName = $"{idpConfig.Name}userinfos";
        var infosClient = _httpClientFactory.CreateClient(infosClientName);
        infosClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", parameters.AccessToken);

        var userInfoUri = new Uri(idpConfig.UserInfoEndpoint);
        
        _logger.LogInformation("Making request to {userInfoEndpoint}", userInfoUri);
        var userInfoResponse = await infosClient.GetAsync(userInfoUri.PathAndQuery);
        if (!userInfoResponse.IsSuccessStatusCode)
        {
            _logger.LogError("Failed to get user info");
            throw new BadRequestException("Failed to get user info");
        }
        _logger.LogInformation("User info retrieved");
        
        var content = await userInfoResponse.Content.ReadAsStringAsync();
        var userInfoDictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(content);
        var userMappingDictionary = JsonSerializer.Serialize(idpConfig.UserClaims);
        var mappings = JsonSerializer.Deserialize<Dictionary<string, object>>(userMappingDictionary);

        var mappedUser = new Dictionary<string, object>();

        _logger.LogInformation("Mapping user infos");
        foreach (var (key, value) in userInfoDictionary)
        {
            var destinationClaim = mappings.FirstOrDefault(m => m.Value.ToString() == key).Key;
            if (!string.IsNullOrEmpty(destinationClaim))
            {
                mappedUser.Add(destinationClaim, value);
            }
        }
        
        if (mappedUser.Count == 0)
        {
            _logger.LogError("No user mapping found");
            throw new Exception("No user mapping found");
        }
        
        _logger.LogInformation("User info mapped successfully");

        return JsonSerializer.Deserialize<UserInfos>(JsonSerializer.Serialize(mappedUser));
    }
    
    private string BuildLoginUri(AuthenticationParameters parameters)
    {

        var idpConfig = _authConfiguration.IdentityProviders.FirstOrDefault(idp => idp.Name == parameters.IdentityProvider);
        if (idpConfig is null) throw new Exception($"Invalid IDP: {parameters.IdentityProvider}");
        
        var queryParams = new Dictionary<string, string>
        {
            ["client_id"] = idpConfig.ClientId,
            ["response_type"] = idpConfig.ResponseType,
            ["scope"] = idpConfig.Scope,
            ["redirect_uri"] = idpConfig.RedirectUri,
            ["state"] = parameters.State,
            ["code_challenge"] = parameters.Challenge,
            ["code_challenge_method"] = "S256"
        };

        var baseUrl = idpConfig.CodeEndpoint;
        var query = string.Join("&", queryParams.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"));
   
        return $"{baseUrl}?{query}";
    }
    
    private async Task<TokenResponse> ExchangeCodeForTokens(AuthenticationParameters parameters)
    {
        _logger.LogInformation("Exchanging authorization code for tokens");
        var idpConfig = _authConfiguration.IdentityProviders.FirstOrDefault(idp => idp.Name == parameters.IdentityProvider);
        if (idpConfig is null) throw new BadRequestException($"Invalid IDP: {parameters.IdentityProvider}");
        _logger.LogInformation("Found idp config for {idpName}", idpConfig.Name);
        
        var tokenRequest = new Dictionary<string, string>
        {
            ["grant_type"] = idpConfig.GrantType,
            ["code"] = parameters.AuthorizationCode,
            ["redirect_uri"] = idpConfig.RedirectUri,
            ["client_id"] = idpConfig.ClientId,
            ["code_verifier"] = parameters.ChallengeVerifier,
        };
        
        if(!string.IsNullOrEmpty(idpConfig.ClientSecret)) tokenRequest.Add("client_secret", idpConfig.ClientSecret);

        var clientName = $"{parameters.IdentityProvider}token".ToLower();

        var tokenClient = _httpClientFactory.CreateClient(clientName);
        var userTokenUri = new Uri(idpConfig.TokenEndpoint);

        _logger.LogInformation("Making request to {tokenEndpoint}", userTokenUri);
        var response = await tokenClient.PostAsync(userTokenUri.PathAndQuery, 
            new FormUrlEncodedContent(tokenRequest));

        if (!response.IsSuccessStatusCode)
            throw new BadRequestException("Token exchange failed");
        
        _logger.LogInformation("Token exchange successful");

        var content = await response.Content.ReadAsStringAsync();
        if (string.IsNullOrEmpty(content)) throw new BadRequestException("Failed to parse token response");
        return JsonSerializer.Deserialize<TokenResponse>(content);
    }
}