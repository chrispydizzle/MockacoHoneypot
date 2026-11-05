using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Serilog;
using System.Collections.Generic;
using System.IO;
using System;
using System.Threading.Tasks;

namespace Mockaco
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            using var host = CreateHostBuilder(args).Build();
            await host.RunAsync();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.ConfigureAppConfiguration((context, configuration) =>
                    {
                        var settings = Path.Combine(AppContext.BaseDirectory, "Settings");
                        var switchMappings = new Dictionary<string, string>() {
                            {"--path", "Honeypot:ProfilesPath" },
                            {"--logs", "Serilog:WriteTo:0:Args:path" },
                            {"--dryrun", "Honeypot:DisableRequestLogging" }
                        };
                        configuration.AddJsonFile(Path.Combine(settings, "appsettings.json"), optional: false)
                            .AddJsonFile(Path.Combine(settings, $"appsettings.{context.HostingEnvironment.EnvironmentName}.json"), optional: true)
                            .AddEnvironmentVariables();
                        configuration.AddCommandLine(args, switchMappings);
                    })
                    .UseStartup<Startup>();
                }).UseSerilog((context, loggerConfiguration) => loggerConfiguration.ReadFrom.Configuration(context.Configuration));
    }
}