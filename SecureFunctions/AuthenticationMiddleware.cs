using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace SecureFunctions
{
    public class AuthenticationMiddleware : IFunctionsWorkerMiddleware
    {
        private readonly AzureAdConfig _config;
        private TokenValidationParameters _validationParameters;
        public AuthenticationMiddleware(IOptions<AzureAdConfig> config)
        {
            _config = config.Value;
        }
        public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
        {
            var logger = context.GetLogger("Authentication");
            var headerData = context.BindingContext.BindingData["headers"] as string;
            var headers = JsonSerializer.Deserialize<Dictionary<string, string>>(headerData);
            if (headers.ContainsKey("Authorization"))
            {
                var authorization = headers["Authorization"];
                var bearerHeader = AuthenticationHeaderValue.Parse(authorization);
                await Authenticate(context, bearerHeader, logger).ConfigureAwait(false);
            }

            await next(context).ConfigureAwait(false);
        }

        private async Task Authenticate(FunctionContext context, AuthenticationHeaderValue authenticationHeader, ILogger logger)
        {
            var token = authenticationHeader.Parameter;
            try
            {
                var (t, principal) = await Validate(token).ConfigureAwait(false);
                context.Items.Add("roles", principal.FindAll(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToList());
                context.Items.Add("name", principal.Identity.Name);
                context.Items.Add("isAuthenticated", principal.Identity.IsAuthenticated);
            }
            catch (SecurityTokenExpiredException)
            {
                context.Items.Add("Auth.Error", "Token has expired");
            }
            catch (SecurityTokenInvalidAudienceException)
            {
                context.Items.Add("Auth.Error", "Invalid audience");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to validate token");
                context.Items.Add("Auth.Error", "Failed to validate token");
            }
        }

        private async Task ConfigureValidation()
        {
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{_config.Instance}common/v2.0/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
            var oidcConfig = await configManager.GetConfigurationAsync().ConfigureAwait(false);
            var validAudiences = new string[] { _config.ClientId };
            if (!_config.ClientId.StartsWith("api://"))
            {
                validAudiences = validAudiences.Append($"api://{_config.ClientId}").ToArray();
            }

            _validationParameters = new TokenValidationParameters
            {
                ValidAudiences = validAudiences,
                ValidateAudience = true,
                ValidateIssuer = true,
                IssuerSigningKeys = oidcConfig.SigningKeys,
                ValidIssuer = $"https://sts.windows.net/{_config.TenantId}/",
                ValidateLifetime = true
            };
        }

        public async Task<(JwtSecurityToken, ClaimsPrincipal)> Validate(string token)
        {
            await ConfigureValidation().ConfigureAwait(false);

            var tokenHandler = new JwtSecurityTokenHandler();
            var result = tokenHandler.ValidateToken(token, _validationParameters, out var jwt);

            return (jwt as JwtSecurityToken, result);
        }
    }
}