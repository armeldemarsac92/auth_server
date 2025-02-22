using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace AuthServer.Web.Extensions;

public static class SecurityPolicyExtensions  
{
    public static IServiceCollection AddSecurityPolicies(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder().AddPolicy("Admin", policy =>
            {
                policy.RequireRole("Admin")
                    .RequireAuthenticatedUser();
            })
            .AddPolicy("User", policy =>
            {
                policy.RequireRole("User")
                    .RequireAuthenticatedUser();
            })
            .AddPolicy("Authenticated", policy =>
            {
                policy.RequireAuthenticatedUser()
                    .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
            });
        
        return services;
    }
}