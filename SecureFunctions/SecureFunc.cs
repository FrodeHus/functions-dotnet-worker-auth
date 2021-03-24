using System.Collections.Generic;
using System.Net;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;

namespace SecureFunctions
{
    public static class SecureFunc
    {
        [Function("SecureFunc")]
        public static HttpResponseData Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequestData req,
            FunctionContext executionContext)
        {
            var logger = executionContext.GetLogger("SecureFunc");
            if (!executionContext.IsAuthenticated())
            {
                logger.LogWarning("User is not authorized");
                var resp = req.CreateResponse(HttpStatusCode.Unauthorized);
                resp.Headers.Add("Content-Type", "text/plain; charset=utf-8");
                resp.WriteString(executionContext.GetAuthenticationError());
                return resp;
            }

            if (!executionContext.IsInRole("My.App.Role"))
            {
                logger.LogWarning("User does not have correct role");
                var resp = req.CreateResponse(HttpStatusCode.Forbidden);
                resp.Headers.Add("Content-Type", "text/plain; charset=utf-8");
                resp.WriteString("User does not have correct roles assigned");
                return resp;
            }

            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "text/plain; charset=utf-8");

            response.WriteString("You have access!");

            return response;
        }
    }
}
