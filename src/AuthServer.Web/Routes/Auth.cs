namespace AuthServer.Web.Routes;

public static partial class ApiRoutes
{
    public static class Auth
    {
        private const string Base = $"{BaseApi}/auth";

        public const string Login = $"{Base}/login";
        public const string SimpleLogin = $"{Base}/simple-login";
        public const string Register = $"{Base}/register";
        public const string Refresh = $"{Base}/refresh";
        public const string ConfirmEmail = $"{Base}/confirm-email/{{userId}}/{{token}}";
        public const string ResendConfirmation = $"{Base}/resend-confirmation";
        public const string ForgotPassword = $"{Base}/forgot-password";
        public const string ResetPassword = $"{Base}/reset-password";
        public const string Verify2FA = $"{Base}/verify-2fa";
        
        public const string ExternalLogin = $"{Base}/external-login/{{provider}}";
        public const string ExternalCallback = $"{Base}/external-callback";

        public const string HealthCheck = $"{Base}/healthcheck";
    }
}