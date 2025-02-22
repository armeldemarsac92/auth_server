namespace AuthServer.Web.Extensions;

public static class Helpers
{
    public static string GetUriParameterFromHttpContext(this HttpContext context, string filter)
    {
        var code = context.Request.Query[filter].ToString();
        if (string.IsNullOrEmpty(code)) throw new ArgumentException($"No {filter} found in the http context.");
        return code;
    }
    
    public static string GetPathFromHttpContext(this HttpContext context, string filter)
    {
        var code = context.GetRouteValue(filter)?.ToString();
        if (string.IsNullOrEmpty(code)) throw new ArgumentException($"No {filter} found in the http context.");
        return code;
    }
}