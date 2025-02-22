using AuthServer.Contracts.Database;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.Web.Extensions;

public static class IdentityExtensions
{
    public static IServiceCollection AddIdentity(this IServiceCollection services)
    {
        services.AddIdentity<User, Role>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 8;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = true;

                options.User.RequireUniqueEmail = true;
                options.SignIn.RequireConfirmedEmail = true;

                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
    
                options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
                options.Tokens.AuthenticatorIssuer = "Epitech Project";
    
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddRoles<Role>()
            .AddDefaultTokenProviders()
            .AddApiEndpoints();
        
        return services;
    }
}