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
        public AuthenticationMiddleware(IOptions<AzureAdConfig> config)
        {
            _config = config.Value;
        }
        public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
        {
            var logger = context.GetLogger<AuthenticationMiddleware>();
            var headerData = context.BindingContext.BindingData["headers"] as string;
            var headers = JsonSerializer.Deserialize<Dictionary<string, string>>(headerData);
            var authorization = headers["Authorization"];
            var bearerHeader = AuthenticationHeaderValue.Parse(authorization);
            var token = bearerHeader.Parameter;
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

            await next(context).ConfigureAwait(false);
        }

        private async Task<TokenValidationParameters> ConfigureValidation()
        {
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{_config.Instance}common/v2.0/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
            var oidcConfig = await configManager.GetConfigurationAsync().ConfigureAwait(false);

            return new TokenValidationParameters
            {
                ValidAudiences = new string[] { _config.ClientId },
                ValidateAudience = true,
                ValidateIssuer = false,
                IssuerSigningKeys = oidcConfig.SigningKeys,
                ValidateLifetime = true
            };
        }

        public async Task<(JwtSecurityToken, ClaimsPrincipal)> Validate(string token)
        {
            var validationParameters = await ConfigureValidation().ConfigureAwait(false);

            var tokenHandler = new JwtSecurityTokenHandler();
            var result = tokenHandler.ValidateToken(token, validationParameters, out var jwt);

            return (jwt as JwtSecurityToken, result);
        }
    }
}