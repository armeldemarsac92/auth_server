using AuthServer.Contracts.Exceptions;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.Web.Middlewares.ExceptionHandlers;

internal sealed class DatabaseExceptionHandler : IExceptionHandler
{
    private readonly ILogger<DatabaseExceptionHandler> _logger;

    public DatabaseExceptionHandler(ILogger<DatabaseExceptionHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (exception is not DatabaseException databaseException) return false;

        var (statusCode, title) = GetStatusCodeAndTitle(databaseException);

        _logger.LogError(
            databaseException,
            "Database exception occurred: {Message}",
            databaseException.Message);

        var problemDetails = new ProblemDetails
        {
            Status = statusCode,
            Title = title,
            Detail = databaseException.Message
        };

        httpContext.Response.StatusCode = statusCode;

        await httpContext.Response
            .WriteAsJsonAsync(problemDetails, cancellationToken);

        return true;
    }

    private static (int StatusCode, string Title) GetStatusCodeAndTitle(DatabaseException exception) => exception switch
    {
        DatabaseUniqueViolationException => (StatusCodes.Status409Conflict, "Conflict"),
        DatabaseForeignKeyViolationException => (StatusCodes.Status400BadRequest, "Invalid Reference"),
        DatabaseNotNullViolationException => (StatusCodes.Status400BadRequest, "Missing Required Field"),
        DatabasePermissionException => (StatusCodes.Status403Forbidden, "Forbidden"),
        DatabaseObjectNotFoundException => (StatusCodes.Status404NotFound, "Not Found"),
        DatabaseConnectionException => (StatusCodes.Status503ServiceUnavailable, "Service Unavailable"),
        DatabaseTimeoutException => (StatusCodes.Status504GatewayTimeout, "Gateway Timeout"),
        DatabaseConfigurationException => (StatusCodes.Status500InternalServerError, "Server Configuration Error"),
        DatabaseSyntaxException => (StatusCodes.Status400BadRequest, "Invalid Query"),
        _ => (StatusCodes.Status400BadRequest, "Bad Request")
    };
}