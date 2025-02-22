using Amazon.SimpleEmail;
using AuthServer.AWS.SDK.SES;
using Microsoft.Extensions.DependencyInjection;

namespace AuthServer.AWS.SDK.DI;

public static class AddSES
{
    public static IServiceCollection AddSEService(this IServiceCollection services)
    {
        services.AddSingleton<IAmazonSimpleEmailService, AmazonSimpleEmailServiceClient>();
        services.AddSingleton<IEmailService, AwsSesEmailService>();
        return services;
    }
}