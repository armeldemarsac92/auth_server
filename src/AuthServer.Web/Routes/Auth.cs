namespace AuthServer.Web.Routes;

public static partial class ApiRoutes
{
    public static class Auth
    {
        private const string Base = $"{BaseApi}/auth";

        public const string Login = $"{Base}/login";
        public const string Register = $"{Base}/register";
        public const string Update = $"{Base}/update";
        public const string Refresh = $"{Base}/refresh";
        public const string Resend2FaCode = $"{Base}/resend-code";
        
        public const string ExternalLogin = $"{Base}/external-login/{{provider}}";
        public const string ExternalCallback = $"{Base}/external-callback";

        public const string HealthCheck = $"{Base}/healthcheck";
    }
}