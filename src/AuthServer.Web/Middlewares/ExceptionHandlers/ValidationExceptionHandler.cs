using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.Web.Middlewares.ExceptionHandlers;

internal sealed class ValidationExceptionHandler : IExceptionHandler
{
    private readonly ILogger<ValidationExceptionHandler> _logger;

    public ValidationExceptionHandler(ILogger<ValidationExceptionHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (exception is not FluentValidation.ValidationException validationException) return false;

        _logger.LogError(
            validationException,
            "Validation exception occurred: {Message}",
            validationException.Message);
        
        List<string> validationErrors = new List<string>();
        foreach (var error in validationException.Errors)
        {
            validationErrors.Add(error.ErrorMessage);
        }

        var problemDetails = new ProblemDetails
        {
            Status = StatusCodes.Status400BadRequest,
            Type = "https://tools.ietf.org/html/rfc7231#section-6.5.1",
            Title = "One or more validation errors occurred",
            Detail = validationException.Message,
            Extensions = new Dictionary<string, object?>
            {
                { "errors", validationErrors }
            }
        };

        httpContext.Response.StatusCode = problemDetails.Status.Value;

        await httpContext.Response
            .WriteAsJsonAsync(problemDetails, cancellationToken);

        return true;
    }
}