using AuthServer.Contracts.Auth.Response;
using AuthServer.Contracts.Database;
using MassTransit;
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
    public Task<User> CreateUserAsync(UserRecord record, string userRole);
    public Task<User> UpdateUserAsync(UserInfos record, string userRole);
    public Task ConfirmUserEmailAsync(User user, HttpContext httpContext);
}

public class UserService : IUserService
{
    private readonly UserManager<User> _userManager;
    private readonly LinkGenerator _linkGenerator;
    private readonly IEmailSender<User> _emailSender;
    private readonly IPublishEndpoint _publishEndpoint;
    
    private readonly ILogger<UserService> _logger;

    public UserService(
        UserManager<User> userManager, 
        ILogger<UserService> logger, 
        LinkGenerator linkGenerator, 
        IEmailSender<User> emailSender, 
        IPublishEndpoint publishEndpoint)
    {
        _userManager = userManager;
        _logger = logger;
        _linkGenerator = linkGenerator;
        _emailSender = emailSender;
        _publishEndpoint = publishEndpoint;
    }

    public async Task<User> CreateUserAsync(UserRecord record, string userRole)
    {
        try
        {
            _logger.LogInformation("Creating user: {Email}", record.Email);
            var user = new User { UserName = record.Email, Email = record.Email, FirstName = record.FirstName, LastName = record.LastName, EmailConfirmed = record.EmailConfirmed, ProfilePicture = record.Picture, CreatedAt = DateTime.Now};
            var result = !string.IsNullOrEmpty(record.Password) ? await _userManager.CreateAsync(user, record.Password): await _userManager.CreateAsync(user);
            if (!result.Succeeded) throw new Exception(result.Errors.First().Description);
            _logger.LogInformation("User created: {Email}", user.Email);
            _logger.LogInformation("Adding user {Email} to role: {UserRole}", user.Email, userRole);
            await _userManager.AddToRoleAsync(user, userRole);
            _logger.LogInformation("User {Email} added to role: {UserRole}", user.Email, userRole);
            await _publishEndpoint.Publish(user);
            return user;
        }
        catch (Exception ex)
        {
            _logger.LogError("Error creating user: {Message}", ex.Message);
            throw;
        }
    }

    public async Task<User> UpdateUserAsync(UserInfos record, string userRole)
    {
        try
        {
            _logger.LogInformation("Updating user: {Email}", record.Email);
            var user = new User {Email = record.Email, FirstName = record.GivenName, LastName = record.FamilyName, ProfilePicture = record.Picture};
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded) throw new Exception(result.Errors.First().Description);
            _logger.LogInformation("User updated: {Email}", user.Email);
            _logger.LogInformation("Adding user {Email} to role: {UserRole}", user.Email, userRole);
            await _userManager.AddToRoleAsync(user, userRole);
            _logger.LogInformation("User {Email} added to role: {UserRole}", user.Email, userRole);
            return user;
        }
        catch (Exception ex)
        {
            _logger.LogError("Error creating user: {Message}", ex.Message);
            throw;
        }
    }

    public async Task ConfirmUserEmailAsync(User user, HttpContext httpContext)
    {
        try
        {
            _logger.LogInformation("Confirming user email: {Email}", user.Email);
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = Uri.EscapeDataString(token);
            var confirmationLink = _linkGenerator.GetUriByName(
                httpContext,
                "ConfirmEmail",
                new { userId = user.Id, token = encodedToken });

            await _emailSender.SendConfirmationLinkAsync(
                user,
                user.Email,
                $"Please confirm your email by clicking this link: {confirmationLink}");
            _logger.LogInformation("Confirmation email sent to: {Email}", user.Email);

        }
        catch (Exception ex)
        {
            _logger.LogError("Error confirming user email: {Message}", ex.Message);
            throw;
        }
    }
}