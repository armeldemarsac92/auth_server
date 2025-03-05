using AuthServer.Contracts.Auth;
using AuthServer.Contracts.Database;
using AuthServer.Contracts.Exceptions;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.Web.Services;

public interface ITwoFaService
{
    public Task VerifyCodeAsync(User user, string code);
    public Task<string> GenerateCodeAsync(User user);
}

public class TwoFaService : ITwoFaService
{
    private readonly UserManager<User> _userManager;
    private readonly ILogger<TwoFaService> _logger;
    
    public TwoFaService(
        UserManager<User> userManager, 
        ILogger<TwoFaService> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }
    public async Task VerifyCodeAsync(User user, string code)
    {
        try
        {
            _logger.LogInformation("Verifying user code for {UserId}", user.Id);

            string providerName;
            switch (user.PreferredTwoFactorProvider)
            {
                case TwoFactorType.Email:
                    _logger.LogInformation("Using email provider");
                    providerName = TokenOptions.DefaultEmailProvider;
                    break;
        
                case TwoFactorType.SMS:
                    _logger.LogInformation("Using SMS provider");
                    providerName = TokenOptions.DefaultPhoneProvider;
                    break;
        
                default:
                    _logger.LogError("Unknown provider type: {provider}", user.PreferredTwoFactorProvider);
                    throw new BadRequestException("Invalid two-factor provider configured.");
            }

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, providerName, code);
            if (!isValid)
            {
                _logger.LogWarning("Invalid verification code for user {UserId}", user.Id);
                throw new BadRequestException("Invalid code.");
            }
        }
        catch (Exception ex)
        {
            await _userManager.AccessFailedAsync(user);
            _logger.LogError("Error verifying user code: {Message} for {UserId}", ex.Message, user.Id);
            throw;
        }
    }

    public async Task<string> GenerateCodeAsync(User user)
    {
        try
        {
            _logger.LogInformation("Generating user code for {UserId}", user.Id);
    
            string providerName;
            switch (user.PreferredTwoFactorProvider)
            {
                case TwoFactorType.Email:
                    _logger.LogInformation("Using email provider");
                    providerName = TokenOptions.DefaultEmailProvider;
                    break;
            
                case TwoFactorType.SMS:
                    _logger.LogInformation("Using SMS provider");
                    providerName = TokenOptions.DefaultPhoneProvider;
                    break;
            
                default:
                    _logger.LogError("Unknown provider type: {provider}", user.PreferredTwoFactorProvider);
                    throw new BadRequestException("Invalid two-factor provider configured.");
            }
    
            return await _userManager.GenerateTwoFactorTokenAsync(user, providerName);
        }
        catch (Exception ex)
        {
            _logger.LogError("Error generating user code: {Message} for {UserId}", ex.Message, user.Id);
            throw;
        }
    }
}