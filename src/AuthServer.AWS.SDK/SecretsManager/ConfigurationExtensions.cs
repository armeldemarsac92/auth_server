using Amazon;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using AuthServer.Contracts.Config;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace AuthServer.AWS.SDK.SecretsManager;

public static class ConfigurationExtensions
{
    public static WebApplicationBuilder AddAwsConfiguration(this WebApplicationBuilder builder, params SecretType[] secretTypes)
    {
        var baseEnv = builder.Environment.IsDevelopment()? "dev" : "prod";
        ConfigureAwsSecrets(builder.Configuration, baseEnv, secretTypes);
        AddConfigurationOptions(builder.Services, builder.Configuration, secretTypes);
        return builder;
    }

    public static IHostBuilder AddAwsConfiguration(this IHostBuilder hostBuilder, params SecretType[] secretTypes)
    {
        
        hostBuilder.ConfigureAppConfiguration((context, builder) =>
        {
            var baseEnv = context.HostingEnvironment.IsDevelopment()? "dev" : "prod";
            ConfigureAwsSecrets(builder, baseEnv, secretTypes);
        });

        hostBuilder.ConfigureServices((context, services) =>
        {
            AddConfigurationOptions(services, context.Configuration, secretTypes);
        });

        return hostBuilder;
    }
    
    public static IHostApplicationBuilder AddAwsConfiguration(this IHostApplicationBuilder builder, params SecretType[] secretTypes)
    {
        var baseEnv = builder.Environment.IsDevelopment()? "dev" : "prod";
        ConfigureAwsSecrets(builder.Configuration, baseEnv, secretTypes);
        AddConfigurationOptions(builder.Services, builder.Configuration, secretTypes);
        return builder;
    }
    
    public static void ConfigureAwsSecrets(this IConfigurationBuilder builder, string baseEnv, params SecretType[] secretTypes)
    {
        string sharedBase = $"tdev702/{baseEnv}/shared/";
        
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

            case SecretType.Networking:
                services.Configure<NetworkConfiguration>(configuration.GetSection("networking"));
                services.AddSingleton(sp => 
                    configuration.GetSection("networking").Get<NetworkConfiguration>() 
                    ?? throw new InvalidOperationException("Network configuration not found"));
                break;
                
            case SecretType.Stripe:
                services.Configure<StripeConfiguration>(configuration.GetSection("stripe"));
                services.AddSingleton(sp => 
                    configuration.GetSection("stripe").Get<StripeConfiguration>() 
                    ?? throw new InvalidOperationException("Stripe configuration not found"));
                break;
            
            case SecretType.Auth:
                services.Configure<AuthConfiguration>(configuration.GetSection("auth"));
                services.AddSingleton(sp => 
                    configuration.GetSection("auth").Get<AuthConfiguration>() 
                    ?? throw new InvalidOperationException("Auth configuration not found"));
                break;
            
            case SecretType.Cache:
                services.Configure<CacheConfiguration>(configuration.GetSection("cache"));
                services.AddSingleton(sp => 
                    configuration.GetSection("cache").Get<CacheConfiguration>() 
                    ?? throw new InvalidOperationException("Cache configuration not found"));
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