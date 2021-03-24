using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Azure.Functions.Worker.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace SecureFunctions
{
    public class Program
    {
        public static void Main()
        {
            var host = new HostBuilder()
                .ConfigureAppConfiguration(c =>
                {
                    c.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
                    c.Build();
                })
                .ConfigureServices((b, s) =>
                {
                    s.AddOptions();
                    s.Configure<AzureAdConfig>(b.Configuration.GetSection("AzureAd"));
                })
                .ConfigureFunctionsWorkerDefaults(app => app.UseMiddleware<AuthenticationMiddleware>())
                .Build();

            host.Run();
        }
    }
}