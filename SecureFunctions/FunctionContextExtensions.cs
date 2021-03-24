using System.Collections.Generic;
using System.Linq;
using Microsoft.Azure.Functions.Worker;

namespace SecureFunctions
{
    public static class FunctionContextExtensions
    {
        public static bool IsInRole(this FunctionContext context, string role)
        {
            if (!context.Items.ContainsKey("roles"))
            {
                return false;
            }
            if (context.Items["roles"] is not List<string> roles)
            {
                return false;
            }

            return roles.Any(r => r == role);
        }

        public static bool IsAuthenticated(this FunctionContext context)
        {
            if (!context.Items.ContainsKey("isAuthenticated"))
            {
                return false;
            }
            if (context.Items["isAuthenticated"] is not bool authenticated)
            {
                return false;
            }

            return authenticated;
        }

        public static string GetAuthenticationError(this FunctionContext context)
        {
            if (!context.Items.ContainsKey("Auth.Error"))
            {
                return null;
            }
            return context.Items["Auth.Error"] as string;
        }
    }
}