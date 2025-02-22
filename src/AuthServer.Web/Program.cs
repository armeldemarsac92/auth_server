using AuthServer.AWS.SDK.CloudWatch;
using AuthServer.AWS.SDK.DI;
using AuthServer.AWS.SDK.SecretsManager;
using AuthServer.Contracts.Config;
using AuthServer.Contracts.Database;
using AuthServer.Stripe.SDK.DI;
using AuthServer.Web.Extensions;
using AuthServer.Web.Middlewares.ExceptionHandlers;
using Microsoft.EntityFrameworkCore;
using Serilog;
using Serilog.Debugging;

var builder = WebApplication.CreateBuilder(args);

builder.AddAwsConfiguration(SecretType.Database, SecretType.Auth, SecretType.Stripe);

Log.Logger = new LoggerConfiguration()
    .ConfigureSerilog(builder.Configuration)
    .CreateLogger();
builder.Host.UseSerilog();
SelfLog.Enable(Console.Error);   

var databaseConfiguration = builder.Configuration.GetSection("database").Get<DatabaseConfiguration>() ?? throw new InvalidOperationException("Database configuration not found");
var connectionString = databaseConfiguration.DbConnectionString;
var authConfiguration = builder.Configuration.GetSection("auth").Get<AuthConfiguration>() ?? throw new InvalidOperationException("Auth configuration not found");
var stripeConfiguration = builder.Configuration.GetSection("stripe").Get<StripeConfiguration>()?? throw new InvalidOperationException("Stripe configuration not found");
var services = builder.Services;
services.AddSEService();
services.AddDistributedMemoryCache();
services.AddStripeServices(stripeConfiguration);
services.AddMessaging();
services.AddEndpointsApiExplorer();
services.AddAuthServices(authConfiguration);

services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(connectionString, b => b.MigrationsAssembly("Tdev702.Auth")));

services.AddSwagger("Auth Server");
services.AddIdentity();
services.AddAuth(authConfiguration);
services.AddAntiforgery(options => 
{
    options.HeaderName = "X-XSRF-TOKEN";
    options.Cookie.Name = "XSRF-TOKEN";
    options.Cookie.HttpOnly = true; 
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax; 
});

services.AddSecurityPolicies();

services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(authConfiguration.CorsAllowOrigin)
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

services.AddProblemDetails();
services.AddExceptionHandler<BadRequestExceptionHandler>();
services.AddExceptionHandler<ConflictExceptionHandler>();
services.AddExceptionHandler<NotFoundExceptionHandler>();
services.AddExceptionHandler<DatabaseExceptionHandler>();
services.AddExceptionHandler<GlobalExceptionHandler>();

var app = builder.Build();

app.UseExceptionHandler();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.ApplyMigrations();
}

app.UseHttpsRedirection(); 
app.UseCors();
app.UseAuthentication(); 
app.UseAuthorization();

app.MapApiEndpoints();

app.Run();