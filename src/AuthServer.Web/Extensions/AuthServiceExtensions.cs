using AuthServer.Contracts.Config;
using AuthServer.Contracts.Database;
using AuthServer.Web.Services;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.Web.Extensions;

public static partial class AuthServiceExtensions
{
    public static IServiceCollection AddAuthServices(this IServiceCollection services, AuthConfiguration authConfiguration)
    {

        foreach (var identityProvider in authConfiguration.IdentityProviders)
        {
            var tokenClientName = $"{identityProvider.Name}token";
            services.AddHttpClient(tokenClientName, options =>
            {
                var tokenUri = new Uri(identityProvider.TokenEndpoint);
                options.BaseAddress = new Uri($"{tokenUri.Scheme}://{tokenUri.Host}");
            });
           
            var userInfosClientName = $"{identityProvider.Name}userinfos";
            services.AddHttpClient(userInfosClientName, options =>
            {
                var userInfoUri = new Uri(identityProvider.UserInfoEndpoint); 
                options.BaseAddress = new Uri($"{userInfoUri.Scheme}://{userInfoUri.Host}");
            });
        }
        
        services.AddScoped<IUserService, UserService>();
        services.AddScoped<IAuthService, AuthService>();
        services.AddSingleton<IKeyService, KeyService>();
        services.AddScoped<ITokenService, TokenService>();
        services.AddScoped<ISecurityService, SecurityService>();
        return services;
    }
}