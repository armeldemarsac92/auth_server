using System.IdentityModel.Tokens.Jwt;
using System.Security;
using System.Text.Json;
using AuthServer.Contracts.Auth;
using AuthServer.Contracts.Config;
using Microsoft.Extensions.Caching.Distributed;

namespace AuthServer.Web.Services;

public interface ISecurityService
{
    Task StoreAuthState(AuthenticationParameters authParameters);
    Task<AuthStateData> ValidateState(string state);
    bool ValidateIdToken(string idToken, string nonce);
    public Dictionary<string, string> MapTokenToUserDict(string idToken);
}

public class SecurityService : ISecurityService
{
   private readonly IDistributedCache _cache;
   private readonly AuthConfiguration _configuration;

   public SecurityService(
       IDistributedCache cache, 
       AuthConfiguration configuration, 
       HttpClient httpClient)
   {
       _cache = cache;
       _configuration = configuration;
   }
   

   public async Task StoreAuthState(AuthenticationParameters authParameters)
   {
       var idpConfig = _configuration.IdentityProviders.FirstOrDefault(idp => idp.Name == authParameters.IdentityProvider);
       if (idpConfig is null) throw new Exception($"Invalid IDP: {authParameters.IdentityProvider}");

       authParameters.FrontEndRedirectUri = idpConfig.FrontEndRedirectUri;
       var stateData = new AuthStateData
       {
           AuthenticationParameters = authParameters,
           Timestamp = DateTime.UtcNow
       };

       await _cache.SetStringAsync(
           $"auth_state:{authParameters.State}",
           JsonSerializer.Serialize(stateData),
           new DistributedCacheEntryOptions
           {
               AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15)
           }
       );
   }

   public async Task<AuthStateData> ValidateState(string state)
   {
       var stateJson = await _cache.GetStringAsync($"auth_state:{state}");
       if (string.IsNullOrEmpty(stateJson))
           throw new SecurityException($"Invalid or expired state: {stateJson}");

       var stateData = JsonSerializer.Deserialize<AuthStateData>(stateJson);
       if (DateTime.UtcNow - stateData.Timestamp > TimeSpan.FromMinutes(15))
           throw new SecurityException("State expired");
       await _cache.RemoveAsync($"auth_state:{state}");

       return stateData;
   }

   public  bool ValidateIdToken(string idToken, string nonce)
   {
       var handler = new JwtSecurityTokenHandler();
       var token = handler.ReadJwtToken(idToken);

       if (token.Payload.Nonce != nonce)
           throw new SecurityException("Invalid nonce");


       return true;
   }

   public Dictionary<string, string> MapTokenToUserDict(string idToken)
       
   {
       var handler = new JwtSecurityTokenHandler();
       var jwtToken = handler.ReadJwtToken(idToken);
       var claims = jwtToken.Claims;
       var claimLookup = claims.GroupBy(c => c.Type)
           .ToDictionary(g => g.Key, g => g.First().Value);
       return claimLookup;
   }
}