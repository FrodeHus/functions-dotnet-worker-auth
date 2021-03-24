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
        public static HttpResponseData Run([HttpTrigger(AuthorizationLevel.Function, "get", "post")] HttpRequestData req,
            FunctionContext executionContext)
        {
            var logger = executionContext.GetLogger("SecureFunc");
            if (!executionContext.IsAuthenticated())
            {
                var resp = req.CreateResponse(HttpStatusCode.Unauthorized);
                resp.WriteString(executionContext.GetAuthenticationError());
                return resp;
            }

            if (!executionContext.IsInRole("My.App.Role"))
            {
                return req.CreateResponse(HttpStatusCode.Forbidden);
            }

            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "text/plain; charset=utf-8");

            response.WriteString("You have access!");

            return response;
        }
    }
}
