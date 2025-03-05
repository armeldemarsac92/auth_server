using AuthServer.Web.Endpoints;

namespace AuthServer.Web.Extensions;

public static class ApiEndpointExtensions  
{
    public static IEndpointRouteBuilder MapApiEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapAuthEndpoints();
        app.MapRoleEndpoints();
        
        var endpoints = app.DataSources.SelectMany(ds => ds.Endpoints).OfType<RouteEndpoint>();
        foreach (var endpoint in endpoints)
        {
            Console.WriteLine($"Registered: {endpoint.RoutePattern.RawText} - Methods: {string.Join(", ", endpoint.Metadata.OfType<HttpMethodMetadata>().SelectMany(m => m.HttpMethods))}");
        }
        
        return app;
    }
}