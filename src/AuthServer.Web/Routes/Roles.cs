namespace AuthServer.Web.Routes;

public static partial class ApiRoutes
{
    private const string BaseApi = "/api";
   
    public static class Roles
    {
        private const string Base = $"{BaseApi}/roles";
       
        public const string GetAll = Base;
        public const string Create = Base;
        public const string Delete = $"{Base}/{{roleName}}";
        public const string AddUserToRole = $"{BaseApi}/users/{{userId}}/roles";
        public const string RemoveUserFromRole = $"{BaseApi}/users/{{userId}}/roles/{{roleName}}";
        public const string GetUserRoles = $"{BaseApi}/users/{{userId}}/roles";
    }


}