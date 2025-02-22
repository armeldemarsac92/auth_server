using Amazon.SimpleEmail;
using Amazon.SimpleEmail.Model;
using AuthServer.Contracts.Config;
using Microsoft.Extensions.Configuration;

namespace AuthServer.AWS.SDK.SES;

public interface IEmailService
{
    Task SendVerificationCodeAsync(string email, string code);
    Task SendEmailAsync(string toEmail, string subject, string message);
}

public class AwsSesEmailService : IEmailService
{
    private readonly IAmazonSimpleEmailService _sesClient;
    private readonly AuthConfiguration _configuration;

    public AwsSesEmailService(IAmazonSimpleEmailService sesClient, IConfiguration configuration)
    {
        _sesClient = sesClient;
        _configuration = configuration.GetSection("auth").Get<AuthConfiguration>() ?? throw new InvalidOperationException("Auth configuration not found");
    }

    public async Task SendEmailAsync(string toEmail, string subject, string message)
    {
        try
        {
            var request = new SendEmailRequest
            {
                Source = _configuration.SourceEmail,
                Destination = new Destination
                {
                    ToAddresses = new List<string> { toEmail }
                },
                Message = new Message
                {
                    Subject = new Content { Data = subject },
                    Body = new Body
                    {
                        Text = new Content
                        {
                            Data = message
                        },
                        Html = new Content
                        {
                            Data = $@"
                            <html>
                                <body>
                                    <h2>{subject}</h2>
                                    <p>{message}</p>
                                </body>
                            </html>"
                        }
                    }
                }
            };
            await _sesClient.SendEmailAsync(request);
        }
        catch (Exception ex)
        {
            throw new Exception("Failed to send verification code", ex);
        }
    }

    public async Task SendVerificationCodeAsync(string email, string code)
    {
        var request = new SendEmailRequest
        {
            Source = _configuration.SourceEmail,
            Destination = new Destination
            {
                ToAddresses = new List<string> { email }
            },
            Message = new Message
            {
                Subject = new Content { Data = "Your verification code" },
                Body = new Body
                {
                    Text = new Content
                    {
                        Data = $"Your verification code is: {code}"
                    },
                    Html = new Content
                    {
                        Data = $@"
                            <html>
                                <body>
                                    <h2>Your verification code</h2>
                                    <p>Your verification code is: <strong>{code}</strong></p>
                                </body>
                            </html>"
                    }
                }
            }
        };

        try
        {
            var response = await _sesClient.SendEmailAsync(request);
        }
        catch (Exception ex)
        {
            throw new Exception("Failed to send verification code", ex);
        }
    }
}