using Serilog;

namespace AuthServer.Web.Middlewares.Logging;

public static class RequestEnricher
{
    public static void LogAdditionalInfo(
        IDiagnosticContext diagnosticContext, 
        HttpContext httpContext)
    {
        diagnosticContext.Set(
            "ClientIp", 
            httpContext.Connection.RemoteIpAddress?.ToString());
        diagnosticContext.Set(
            "StatusCode", 
            httpContext.Response.StatusCode.ToString());
        diagnosticContext.Set(
            "RequestMethod", 
            httpContext.Request.Method);
        diagnosticContext.Set(
            "RequestPath", 
            httpContext.Request.Path.ToString());
    }
}