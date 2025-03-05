using System.Security.Claims;
using AuthServer.AWS.SDK.SES;
using AuthServer.Contracts.Auth;
using AuthServer.Contracts.Auth.Request;
using AuthServer.Contracts.Database;
using AuthServer.Contracts.Exceptions;
using MassTransit;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.Web.Services;

public record UserRecord(
    string FirstName,
    string LastName, 
    string Email, 
    bool EmailConfirmed,
    string? Picture,
    string? Password
);
public interface IUserService
{
    public Task RegisterUserAsync(string userEmail, string userRole);
    public Task<AccessTokenResponse> ProvisionUserAsync(AuthenticationParameters parameters);
    public Task<AccessTokenResponse> LoginUserAsync(LoginUserRequest request);
    public Task<AccessTokenResponse> UpdateUserAsync(ClaimsPrincipal claims, UpdateUserRequest request);
    public Task Send2FaCodeAsync(Get2FaCodeRequest request);
}

public class UserService : IUserService
{
    private readonly UserManager<User> _userManager;
    private readonly LinkGenerator _linkGenerator;
    private readonly IEmailSender<User> _emailSender;
    private readonly IEmailService _emailService;
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly ITwoFaService _i2FaService;
    private readonly ITokenService _tokenService;
    private readonly IAuthService _authService;
    private readonly ILogger<UserService> _logger;

    public UserService(
        UserManager<User> userManager, 
        ILogger<UserService> logger, 
        LinkGenerator linkGenerator, 
        IEmailSender<User> emailSender, 
        IPublishEndpoint publishEndpoint, 
        ITwoFaService i2FaService, 
        ITokenService tokenService, 
        IEmailService emailService, 
        IAuthService authService)
    {
        _userManager = userManager;
        _logger = logger;
        _linkGenerator = linkGenerator;
        _emailSender = emailSender;
        _publishEndpoint = publishEndpoint;
        _i2FaService = i2FaService;
        _tokenService = tokenService;
        _emailService = emailService;
        _authService = authService;
    }

    public async Task<AccessTokenResponse> LoginUserAsync(LoginUserRequest request)
    {
        _logger.LogInformation("Logging in user: {Email}", request.Email);
        var user = await _userManager.FindByEmailAsync(request.Email);
        CheckUser(user);
        _logger.LogInformation("Verifying 2FA code for user {userId}", user.Id);
        await _i2FaService.VerifyCodeAsync(user, request.TwoFactorCode);
        _logger.LogInformation("2FA code verified for user {UserId}", user.Id);
        
        if (user.EmailConfirmed == false)
        {
            _logger.LogInformation("User {UserId} email not confirmed yet.", user.Id);
            user.EmailConfirmed = true;
            var result = await _userManager.UpdateAsync(user);
            CheckResult(result);
            _logger.LogInformation("User {UserId} email confirmed.", user.Id);
        }
        
        return await _tokenService.GetAccessTokenAsync(user);
    }
    
    public async Task RegisterUserAsync(string userEmail, string userRole)
    {
        _logger.LogInformation("Creating user: {Email}", userEmail);
        var user = new User { UserName = userEmail, Email = userEmail, PreferredTwoFactorProvider = TwoFactorType.Email, CreatedAt = DateTime.UtcNow};
        await CreateUserDataAsync(user, userRole);
        
        _logger.LogInformation("Sending confirmation code to user {UserId}", user.Id);
        await _userManager.SetTwoFactorEnabledAsync(user, true);
        var code = await _i2FaService.GenerateCodeAsync(user);
        await _emailService.SendVerificationCodeAsync(user.Email, code);
        _logger.LogInformation("Confirmation code sent to user {UserId}", user.Id);
    }        
    
    public async Task<AccessTokenResponse> UpdateUserAsync(ClaimsPrincipal claims, UpdateUserRequest request)
    {
        var user = await _userManager.GetUserAsync(claims);
        CheckUser(user);

        _logger.LogInformation("Updating user: {Email}", user.Email);
        user.FirstName = request.FirstName;
        user.LastName = request.LastName;
        user.ProfilePicture = request.ProfilePicture;

        return await UpdateUserDataAsync(user);
    }
    
    public async Task<AccessTokenResponse> ProvisionUserAsync(AuthenticationParameters authParameters)
    {
        var userInfos = await _authService.GetUserInfosAsync(authParameters);
        _logger.LogInformation("Provisioning user: {Email}", userInfos.Email);
        
        var userRole = "User";
        if (authParameters.IdentityProvider == "aws")
        {
            _logger.LogInformation("User role set to admin");
            userRole = "Admin";
        }
        
        _logger.LogInformation("Creating user login informations for idp {idp}", authParameters.IdentityProvider);
        var userLoginInfo = new UserLoginInfo(authParameters.IdentityProvider, userInfos.Sub, authParameters.IdentityProvider);
        
        _logger.LogInformation("Checking if user {Email} already exists", userInfos.Email);
        var user = await _userManager.FindByEmailAsync(userInfos.Email);
        if (user != null)
        {
            _logger.LogInformation("User {UserId} already exists, updating its role", user.Id);
            var result = await _userManager.AddToRoleAsync(user, userRole);
            CheckResult(result);
            _logger.LogInformation("Updating user login");
            result = await _userManager.AddLoginAsync(user, userLoginInfo);
            CheckResult(result);
            _logger.LogInformation("Disabling 2FA for user {UserId}", user.Id);
            user.TwoFactorEnabled = false;
            _logger.LogInformation("Updating user infos");
            return await UpdateUserDataAsync(user);
        }

        _logger.LogInformation("User {Email} doesn't exist, creating it", userInfos.Email);
        user = new User { UserName = userInfos.Email, Email = userInfos.Email, FirstName = userInfos.GivenName, LastName = userInfos.FamilyName, ProfilePicture = userInfos.Picture, CreatedAt = DateTime.UtcNow};
        await CreateUserDataAsync(user, userRole);
        _logger.LogInformation("Updating user login");
        var loginResult = await _userManager.AddLoginAsync(user, userLoginInfo);
        CheckResult(loginResult);
        return await _tokenService.GetAccessTokenAsync(user);

    }    

    public async Task Send2FaCodeAsync(Get2FaCodeRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        CheckUser(user);
        _logger.LogInformation("Sending 2FA code to user {UserId}", user.Id);
        
        _logger.LogInformation("Sending confirmation code to user {UserId}", user.Id);
        var code = await _i2FaService.GenerateCodeAsync(user);
        await _emailService.SendVerificationCodeAsync(user.Email, code);
        _logger.LogInformation("Confirmation code sent to user {UserId}", user.Id);
    }

    private async Task CreateUserDataAsync(User userToCreate, string userRole)
    {
        var creationResult = await _userManager.CreateAsync(userToCreate);
        CheckResult(creationResult);
        _logger.LogInformation("User created: {UserId}", userToCreate.Id);
        _logger.LogInformation("Adding user {UserId} to role: {UserRole}", userToCreate.Id, userRole);
        var roleResult = await _userManager.AddToRoleAsync(userToCreate, userRole);
        CheckResult(roleResult);
        _logger.LogInformation("User {UserId} added to role: {UserRole}", userToCreate.Id, userRole);
        _logger.LogInformation("Publishing user {UserId} to the stripe event bus to generate its stripe id.", userToCreate.Id);
        await _publishEndpoint.Publish(userToCreate);
    }

    private async Task<AccessTokenResponse> UpdateUserDataAsync(User user)
    {
        var result = await _userManager.UpdateAsync(user);
        CheckResult(result);
        _logger.LogInformation("User {UserId} updated.", user.Id);
        return await _tokenService.GetAccessTokenAsync(user);
    }
    
    private void CheckUser(User? user)
    {
        if (user == null) throw new BadRequestException("User not found");
        _logger.LogInformation("User {UserId} found.", user.Id);
    }
    
    private void CheckResult(IdentityResult result)
    {
        if (result.Errors.Any())
        {
            _logger.LogError("Operation failed with {ErrorCount} errors.", 
                result.Errors.Count());
    
            var errorMessages = result.Errors.Select(e => e.Description).ToList();
    
            foreach (var error in result.Errors)
            {
                _logger.LogError("Error code {Code}: {Description}", 
                    error.Code, error.Description);
            }
    
            throw new BadRequestException(
                $"Operation failed: {string.Join(", ", errorMessages)}");
        }
    }
}