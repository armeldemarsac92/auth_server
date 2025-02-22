using System.Security.Claims;
using AuthServer.AWS.SDK.SES;
using AuthServer.Contracts.Auth;
using AuthServer.Contracts.Auth.Request;
using AuthServer.Contracts.Database;
using AuthServer.Contracts.Exceptions;
using AuthServer.Web.Routes;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.Web.Endpoints;

public static class SecurityEndpoints
{
    private const string ContentType = "application/json";
    private const string Tags = "Security";
    public static IEndpointRouteBuilder MapSecurityEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet(ApiRoutes.Security.XsrfToken, GetXsrfToken)
            .WithName("GetXsrfToken")
            .WithTags(Tags);
        
        app.MapPost(ApiRoutes.Security.Enable, Setup2FA)
            .Accepts<Setup2FaRequest>(ContentType)
            .RequireAuthorization("Authenticated")
            .WithName("Enable2FA")
            .WithTags(Tags);

        app.MapPost(ApiRoutes.Security.Verify, Verify2fa)
            .Accepts<Verify2FaRequest>(ContentType)
            .RequireAuthorization("Authenticated")
            .WithName("Verify2FA")
            .WithTags(Tags);

        app.MapPost(ApiRoutes.Security.Disable, Disable2fa)
             .RequireAuthorization("Authenticated")
            .WithName("Disable2FA")
            .WithTags(Tags);
        
        return app;
    }
    
    private static IResult GetXsrfToken(IAntiforgery antiforgery, HttpContext context)
    {
        var tokens = antiforgery.GetAndStoreTokens(context);
        return Results.Ok(new { token = tokens.RequestToken });
    }
    
    private static async Task<IResult> Setup2FA(
        UserManager<User> userManager,
        ClaimsPrincipal claimsPrincipal,
        Setup2FaRequest request,
        TwoFactorType twoFactorType,
        IEmailService emailService)
    {
        var user = await userManager.GetUserAsync(claimsPrincipal);
        if (user == null)
            throw new BadRequestException("User not found");

        switch (twoFactorType)
        {
            case TwoFactorType.Authenticator:
                return await SetupAuthenticator(userManager, user);
                
            case TwoFactorType.Email:
                return await SetupEmail(userManager, user, emailService);
                
            case TwoFactorType.SMS:
                if (string.IsNullOrEmpty(request.PhoneNumber))
                    throw new BadRequestException("Phone number is required for SMS 2FA");
                return await SetupSMS(userManager, user, request.PhoneNumber);
                
            default:
                throw new BadRequestException("Invalid 2FA type");
        }
    }

    private static async Task<IResult> SetupAuthenticator(UserManager<User> userManager, User user)
    {
        var unformattedKey = await userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(unformattedKey))
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
            unformattedKey = await userManager.GetAuthenticatorKeyAsync(user);
        }

        var authenticatorUri = GenerateQrCodeUri(user.Email!, unformattedKey!);
        
        user.PreferredTwoFactorProvider = TwoFactorType.Authenticator;
        await userManager.UpdateAsync(user);

        return Results.Ok(new
        {
            Type = TwoFactorType.Authenticator,
            SharedKey = unformattedKey,
            AuthenticatorUri = authenticatorUri
        });
    }

    private static async Task<IResult> SetupEmail(UserManager<User> userManager, User user, IEmailService emailService)
    {
        var token = await userManager.GenerateTwoFactorTokenAsync(user, 
            TokenOptions.DefaultEmailProvider);
        
        await emailService.SendVerificationCodeAsync(user.Email!, token);
        
        user.PreferredTwoFactorProvider = TwoFactorType.Email;
        await userManager.UpdateAsync(user);
        
        return Results.Ok(new
        {
            Type = TwoFactorType.Email,
            Message = "Verification code sent to your email"
        });
    }

    private static async Task<IResult> SetupSMS(UserManager<User> userManager, User user, string phoneNumber)
    {
        var setPhoneResult = await userManager.SetPhoneNumberAsync(user, phoneNumber);
        if (!setPhoneResult.Succeeded)
            throw new BadRequestException($"Error setting phone number :{setPhoneResult.Errors}");

        var token = await userManager.GenerateTwoFactorTokenAsync(user, 
            TokenOptions.DefaultPhoneProvider);
        
        user.PreferredTwoFactorProvider = TwoFactorType.SMS;
        await userManager.UpdateAsync(user);
        
        return Results.Ok(new
        {
            Type = TwoFactorType.SMS,
            Message = "Verification code sent to your phone"
        });
    }

    private static async Task<IResult> Verify2fa(
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        ClaimsPrincipal claimsPrincipal,
        Verify2FaRequest request)
    {
        var user = await userManager.GetUserAsync(claimsPrincipal);
        if (user == null)
            throw new BadRequestException("User not found");

        var verificationCode = request.VerificationCode.Replace(" ", string.Empty).Replace("-", string.Empty);

        var is2FaTokenValid = false;
        
        switch (user.PreferredTwoFactorProvider)
        {
            case TwoFactorType.Authenticator:
                is2FaTokenValid = await userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, verificationCode);
                break;
                
            case TwoFactorType.Email:
                is2FaTokenValid = await userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, verificationCode);
                break;

            case TwoFactorType.SMS:
                is2FaTokenValid = await userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultPhoneProvider, verificationCode);
                break;

            default:
                throw new BadRequestException("Invalid 2FA type");
        }

        if (!is2FaTokenValid)
            throw new BadRequestException("Verification code is invalid.");

        await userManager.SetTwoFactorEnabledAsync(user, true);

        return Results.Ok("2FA has been enabled.");
    }

    private static async Task<IResult> Disable2fa(
        UserManager<User> userManager,
        ClaimsPrincipal claimsPrincipal)
    {
        var user = await userManager.GetUserAsync(claimsPrincipal);
        if (user == null)
            throw new BadRequestException("User not found");

        var disable2faResult = await userManager.SetTwoFactorEnabledAsync(user, false);
        if (!disable2faResult.Succeeded)
            throw new BadRequestException($"Error disabling 2FA :{disable2faResult.Errors}");

        return Results.Ok("2FA has been disabled.");
    }

    private static string GenerateQrCodeUri(string email, string unformattedKey)
    {
        const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
        
        return string.Format(
            AuthenticatorUriFormat,
            Uri.EscapeDataString("Epitech Project"),
            Uri.EscapeDataString(email),
            unformattedKey);
    }

}