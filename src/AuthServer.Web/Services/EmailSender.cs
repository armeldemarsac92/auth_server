using AuthServer.AWS.SDK.SES;
using AuthServer.Contracts.Database;
using Microsoft.AspNetCore.Identity;

namespace AuthServer.Web.Services;

public class EmailSender : IEmailSender<User>
{
    private readonly IEmailService _emailService;
    private readonly ILogger _logger;

    public EmailSender(
        ILogger<EmailSender> logger, IEmailService emailService)
    {
        _logger = logger;
        _emailService = emailService;
    }

    public async Task SendConfirmationLinkAsync(User user, string email, string confirmationLink)
    {
        await _emailService.SendEmailAsync(email, "Confirm your email", $"Hi {user.UserName}. Please confirm your email by clicking on the following link: {confirmationLink}");
    }

    public async Task SendPasswordResetLinkAsync(User user, string email, string resetLink)
    {
        await _emailService.SendEmailAsync(email, "Reset your password", $"Hi {user.UserName}. Please reset your password by clicking on the following link: {resetLink}");
    }

    public async Task SendPasswordResetCodeAsync(User user, string email, string resetCode)
    {
        await _emailService.SendEmailAsync(email, "Reset your password", $"Hi {user.UserName}. Your password reset code is: {resetCode}");
    }
}