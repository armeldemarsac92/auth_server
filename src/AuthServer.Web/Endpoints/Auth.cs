using System.Security.Claims;
using AuthServer.Contracts.Auth.Request;
using AuthServer.Contracts.Config;
using AuthServer.Contracts.Database;
using AuthServer.Web.Routes;
using AuthServer.Web.Services;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;

namespace AuthServer.Web.Endpoints;

public static class AuthEndpoints
{
    private const string ContentType = "application/json";
    private const string Tags = "Auth";
    
    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost(ApiRoutes.Auth.Login, Login)
            .Accepts<LoginRequest>(ContentType)
            .Produces<AccessTokenResponse>()
            .WithName("Login")
            .WithTags(Tags);        
        
        app.MapPost(ApiRoutes.Auth.Register, Register)
            .Accepts<RegisterUserRequest>(ContentType)
            .WithName("Register")
            .WithTags(Tags);
        
        app.MapPost(ApiRoutes.Auth.Update, Update)
            .Accepts<UpdateUserRequest>(ContentType)
            .RequireAuthorization("Authenticated")
            .WithName("Update")
            .WithTags(Tags);

        app.MapPost(ApiRoutes.Auth.Refresh, RefreshToken)
            .Accepts<RefreshTokenRequest>(ContentType)
            .Produces<AccessTokenResponse>()
            .WithName("RefreshToken")
            .RequireAuthorization("Authenticated")
            .WithTags(Tags);

        app.MapPost(ApiRoutes.Auth.Resend2FaCode, Send2FaCode)
            .Accepts<Get2FaCodeRequest>(ContentType)
            .WithName("ResendConfirmation")
            .WithTags(Tags);
        
        app.MapGet(ApiRoutes.Auth.ExternalLogin, OAuthLogin)
            .WithName("ExternalLogin")
            .WithTags(Tags);
        
        app.MapGet(ApiRoutes.Auth.ExternalCallback, OAuthCallback)
            .WithName("ExternalCallback")
            .Produces<AccessTokenResponse>()
            .WithTags(Tags);
        
        app.MapGet(ApiRoutes.Auth.HealthCheck, () => Results.Ok("Healthy"))
           .WithName("HealthCheck")
           .WithTags(Tags);

        return app;
    }

    private static async Task<IResult> Login(
       IUserService userService,
       LoginUserRequest request)
    {
        var token = await userService.LoginUserAsync(request);
        return Results.Ok(token);
    }
        
    private static async Task<IResult> Register(
        IUserService userService,
        RegisterUserRequest request)
    {
        await userService.RegisterUserAsync(request.Email, "User");
        return Results.Ok(new { requiresTwoFactor = true, provider = "Email" });
    }    
    
    private static async Task<IResult> Update(
        IUserService userService,
        ClaimsPrincipal claims,
        UpdateUserRequest request)
    {
        return Results.Ok(await userService.UpdateUserAsync(claims, request));
    }

    private static async Task<IResult> RefreshToken(
        UserManager<User> userManager,
        ITokenService tokenService,
        RefreshTokenRequest request)
    {
        return Results.Ok(await tokenService.RefreshTokenAsync(request.RefreshToken));
    }

    private static async Task<IResult> Send2FaCode(
        IUserService userService,
        Get2FaCodeRequest request)
    {
        await userService.Send2FaCodeAsync(request);
        return Results.Ok(new { requiresTwoFactor = true, provider = "Email" });
    }
    
    private static async Task<IResult> OAuthLogin(
        string provider,
        AuthConfiguration configuration,
        IAuthService authService,
        ISecurityService securityService)
    {
        return Results.Ok(await authService.InstantiateOAuthFlow(provider));
    }

    private static async Task<IResult> OAuthCallback(
    HttpContext context,
    IUserService userService,
    IAuthService authService)
    {
        var authParameters = await authService.GetAuthenticationParameters(context);
        var token = await userService.ProvisionUserAsync(authParameters);
        AddCookies(context, token);
        return Results.Redirect(authParameters.FrontEndRedirectUri);
    }

    private static void AddCookies(HttpContext context, AccessTokenResponse accessTokenResponse)
    {
        var isDev = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development";
        
        context.Response.Cookies.Append("access_token", accessTokenResponse.AccessToken, new CookieOptions
        {
            HttpOnly = false,  
            Secure = true,
            SameSite = SameSiteMode.Lax,   
            Expires = DateTimeOffset.UtcNow.AddHours(2),
            Domain = isDev ? ".localhost":".epitechproject.fr",
            Path = "/"
        });

        context.Response.Cookies.Append("refresh_token", accessTokenResponse.RefreshToken, new CookieOptions
        {
            HttpOnly = false,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Expires = DateTimeOffset.UtcNow.AddDays(7),
            Domain = isDev ? ".localhost":".epitechproject.fr",
            Path = "/"
        });
    }
}