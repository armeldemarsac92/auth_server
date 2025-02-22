namespace AuthServer.Web.Routes;

public static partial class ApiRoutes
{
    public static class Security 
    {
        public const string XsrfToken = $"{BaseApi}/xsrf-token";
        public const string Enable = $"{BaseApi}/2fa/enable/{{type}}";
        public const string Verify = $"{BaseApi}/2fa/verify";
        public const string Disable = $"{BaseApi}/2fa/disable";
    }
    
}