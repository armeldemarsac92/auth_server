using System.Net.Http.Headers;
using System.Text.Json;
using AuthServer.Contracts.Auth;
using AuthServer.Contracts.Auth.Response;
using AuthServer.Contracts.Config;

namespace AuthServer.Web.Services;

public interface IAuthService
{
    public string BuildLoginUri(AuthenticationParameters parameters);
    public Task<TokenResponse> ExchangeCodeForTokens(AuthenticationParameters parameters);
    public Task<FacebookUserInfo> GetFacebookUserInfoAsync(string accessToken);
    public Task<GoogleUserInfo> GetGoogleUserInfoAsync(string accessToken);
    public Task<UserInfos> GetUserInfosAsync(AuthenticationParameters parameters);
}

public class AuthService : IAuthService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly AuthConfiguration _authConfiguration;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        IHttpClientFactory httpClientFactory, 
        AuthConfiguration authConfiguration, 
        ILogger<AuthService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _authConfiguration = authConfiguration;
        _logger = logger;
    }

    public string BuildLoginUri(AuthenticationParameters parameters)
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

    public async Task<TokenResponse> ExchangeCodeForTokens(AuthenticationParameters parameters)
    {
        var idpConfig = _authConfiguration.IdentityProviders.FirstOrDefault(idp => idp.Name == parameters.IdentityProvider);
        if (idpConfig is null) throw new Exception($"Invalid IDP: {parameters.IdentityProvider}");
        
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

        var response = await tokenClient.PostAsync(userTokenUri.PathAndQuery, 
            new FormUrlEncodedContent(tokenRequest));

        if (!response.IsSuccessStatusCode)
            throw new Exception("Token exchange failed");

        var content = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<TokenResponse>(content);
    }
    
    public async Task<FacebookUserInfo> GetFacebookUserInfoAsync(string accessToken)
    {
        try
        {
            _logger.LogInformation("Getting user info from Facebook");
            var infosClient = _httpClientFactory.CreateClient("FacebookUserInfo");
            infosClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", accessToken);

            var userInfoResponse = await infosClient.GetAsync(
                $"me?fields=id,email,first_name,last_name");

            if (!userInfoResponse.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to get user info");
                throw new Exception("Failed to get user info");
            }
            return await userInfoResponse.Content.ReadFromJsonAsync<FacebookUserInfo>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user info");
            throw;
        }
    }
    
    public async Task<GoogleUserInfo> GetGoogleUserInfoAsync(string accessToken)
    {
        try
        {
            _logger.LogInformation("Getting user info from Google");
            var infosClient = _httpClientFactory.CreateClient("GoogleUserInfo");
            infosClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", accessToken);

            var userInfoResponse = await infosClient.GetAsync("userinfo");
            if (!userInfoResponse.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to get user info");
                throw new Exception("Failed to get user info");
            }
            return await userInfoResponse.Content.ReadFromJsonAsync<GoogleUserInfo>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user info");
            throw;
        }
    }    
    
    public async Task<UserInfos> GetUserInfosAsync(AuthenticationParameters parameters)
    {
        try
        {
            var idpConfig = _authConfiguration.IdentityProviders.FirstOrDefault(idp => idp.Name == parameters.IdentityProvider);
            if (idpConfig is null) throw new Exception($"Invalid IDP: {parameters.IdentityProvider}");
            
            _logger.LogInformation("Getting user info from {idp}", idpConfig.Name);
            var infosClientName = $"{idpConfig.Name}userinfos";
            var infosClient = _httpClientFactory.CreateClient(infosClientName);
            infosClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", parameters.AccessToken);

            var userInfoUri = new Uri(idpConfig.UserInfoEndpoint);
            var userInfoResponse = await infosClient.GetAsync(userInfoUri.PathAndQuery);
            if (!userInfoResponse.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to get user info");
                throw new Exception("Failed to get user info");
            }
            var content = await userInfoResponse.Content.ReadAsStringAsync();
            var userInfoDictionary = JsonSerializer.Deserialize<Dictionary<string, object>>(content);
            var userMappingDictionary = JsonSerializer.Serialize(idpConfig.UserClaims);
            var mappings = JsonSerializer.Deserialize<Dictionary<string, object>>(userMappingDictionary);

            var mappedUser = new Dictionary<string, object>();

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

            return JsonSerializer.Deserialize<UserInfos>(JsonSerializer.Serialize(mappedUser));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user info");
            throw;
        }
    }
}