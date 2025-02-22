using Amazon;
using Amazon.CloudWatchLogs;
using Microsoft.Extensions.Configuration;
using Serilog;
using Serilog.Events;
using Serilog.Formatting.Json;
using Serilog.Sinks.AwsCloudWatch;

namespace AuthServer.AWS.SDK.CloudWatch;

public static class CloudWatchExtension
{
    public static LoggerConfiguration ConfigureSerilog(
        this LoggerConfiguration loggerConfiguration,
        IConfiguration configuration)
    {
        return loggerConfiguration
            .ReadFrom.Configuration(configuration)
            .Enrich.FromLogContext()
            .Enrich.WithMachineName()
            .Enrich.WithEnvironmentName()
            .WriteTo.Console(new JsonFormatter())
            .AddAwsCloudWatch(configuration);
    }

    private static LoggerConfiguration AddAwsCloudWatch(
        this LoggerConfiguration loggerConfiguration,
        IConfiguration configuration)
    {
        var env = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production";
        
        var cloudWatchOptions = new CloudWatchSinkOptions
        {
            LogGroupName = $"{configuration["AWS:CloudWatch:LogGroupName"]}-{env}",
            TextFormatter = new JsonFormatter(),
            MinimumLogEventLevel = LogEventLevel.Information,
            BatchSizeLimit = 100,
            QueueSizeLimit = 10000,
            Period = TimeSpan.FromSeconds(10),
            CreateLogGroup = true,
            LogStreamNameProvider = new DefaultLogStreamProvider()
        };

        var client = new AmazonCloudWatchLogsClient(
            RegionEndpoint.GetBySystemName(configuration["AWS:Region"])
        );

        return loggerConfiguration
            .WriteTo.AmazonCloudWatch(
                cloudWatchOptions,
                client)
            .WriteTo.Console(new JsonFormatter());
    }
}