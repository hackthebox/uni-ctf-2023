using Nexus_Void.Helpers;

namespace Nexus_Void.Middleware
{

    public class JWTMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _configuration;

        public JWTMiddleware(RequestDelegate next, IConfiguration configuration)
        {
            _next = next;
            _configuration = configuration;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            string jwtToken = context.Request.Cookies["Token"];

            if (string.IsNullOrEmpty(jwtToken))
            {
                context.Response.Redirect("/");
            }

            JWTHelper _jwtHelper = new JWTHelper(_configuration);

            string validateToken = _jwtHelper.ValidateToken(jwtToken);

            if (validateToken.Equals("false"))
            {
                context.Response.Redirect("/");
            }

            string username = _jwtHelper.getClaims(jwtToken, "username");
            string ID = _jwtHelper.getClaims(jwtToken, "ID");

            if(string.IsNullOrEmpty(username))
            {
                context.Response.Redirect("/");
            }

            context.Items["username"] = username;
            context.Items["ID"] = ID;

            await _next(context);
        }

    }
}
