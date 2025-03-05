using Amazon;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using AuthServer.Contracts.Config;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Stripe;

namespace AuthServer.AWS.SDK.SecretsManager;

public static class ConfigurationExtensions
{
    public static WebApplicationBuilder AddAwsConfiguration(this WebApplicationBuilder builder, params SecretType[] secretTypes)
    {
        ConfigureAwsSecrets(builder.Configuration, secretTypes);
        AddConfigurationOptions(builder.Services, builder.Configuration, secretTypes);
        return builder;
    }

    public static IHostBuilder AddAwsConfiguration(this IHostBuilder hostBuilder, params SecretType[] secretTypes)
    {
        
        hostBuilder.ConfigureAppConfiguration((context, builder) =>
        {
            ConfigureAwsSecrets(builder, secretTypes);
        });

        hostBuilder.ConfigureServices((context, services) =>
        {
            AddConfigurationOptions(services, context.Configuration, secretTypes);
        });

        return hostBuilder;
    }
    
    public static IHostApplicationBuilder AddAwsConfiguration(this IHostApplicationBuilder builder, params SecretType[] secretTypes)
    {
        ConfigureAwsSecrets(builder.Configuration, secretTypes);
        AddConfigurationOptions(builder.Services, builder.Configuration, secretTypes);
        return builder;
    }
    
    public static void ConfigureAwsSecrets(this IConfigurationBuilder builder, params SecretType[] secretTypes)
    {
        var projectName = Environment.GetEnvironmentVariable("PROJECT_NAME") ?? throw new Exception("PROJECT_NAME missing.") ;
        var baseEnv = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? throw new Exception("ASPNETCORE_ENVIRONMENT missing.") ;

        string sharedBase = $"{projectName}/{baseEnv}/shared/";
        
        var filterValues = secretTypes.Select(t => $"{sharedBase}{t.ToString().ToLower()}").ToList();
        
        builder.AddSecretsManager( 
            region: RegionEndpoint.EUCentral1,
            configurator: options =>
            {
                options.KeyGenerator = (_, secretName) => secretName.Replace(sharedBase, string.Empty);
                options.ListSecretsFilters = [new Filter { Key = FilterNameStringType.Name, Values = filterValues}];
            });
    }

    public static IServiceCollection AddConfigurationOptions(this IServiceCollection services, IConfiguration configuration, SecretType[] secretTypes)
{
    foreach (var secretType in secretTypes)
    {
        switch (secretType)
        {
            case SecretType.Database:
                services.Configure<DatabaseConfiguration>(configuration.GetSection("database"));
                services.AddSingleton(sp => 
                    configuration.GetSection("database").Get<DatabaseConfiguration>() 
                    ?? throw new InvalidOperationException("Database configuration not found"));
                break;

            case SecretType.Auth:
                services.Configure<AuthConfiguration>(configuration.GetSection("auth"));
                services.AddSingleton(sp => 
                    configuration.GetSection("auth").Get<AuthConfiguration>() 
                    ?? throw new InvalidOperationException("Auth configuration not found"));
                break;
        }
    }
    return services;
}
    
}

public enum SecretType
{
    Database,
    Networking,
    Stripe,
    Auth,
    Cache
}