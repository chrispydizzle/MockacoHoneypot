using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.IO;
using System.Net.Http;

namespace Mockaco
{
    using Mockaco.Middlewares;
    using Mockaco.Recon;
    using Mockaco.Capture;
    using Mockaco.Responses;

    public class Startup
    {
        private readonly IConfiguration _configuration;

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            var connectionString = _configuration.GetConnectionString("HttpDb");
            services.AddOptions<HoneypotOptions>()
                .Bind(_configuration.GetSection("Honeypot"))
                .PostConfigure(options => options.ConnectionString = connectionString ?? options.ConnectionString)
                .Validate(options => !string.IsNullOrWhiteSpace(options.ConnectionString)
                    && !string.IsNullOrWhiteSpace(options.ProfilesPath)
                    && options.DefaultStatusCode is >= 100 and <= 599
                    && options.UnmatchedStatusCode is >= 100 and <= 599, "Invalid Honeypot configuration")
                .ValidateOnStart();
            services.AddSingleton<IRequestLog, SqlRequestLog>();
            services.AddSingleton(provider =>
            {
                var options = provider.GetRequiredService<IOptions<HoneypotOptions>>().Value;
                var path = Path.IsPathRooted(options.ProfilesPath) ? options.ProfilesPath
                    : Path.Combine(AppContext.BaseDirectory, options.ProfilesPath);
                return ResponseProfiles.Load(path);
            });
            services.AddSingleton<ProfileResponder>();
            services.AddOptions<ReconOptions>()
                .Bind(_configuration.GetSection("Recon"))
                .PostConfigure(options => options.ConnectionString = connectionString ?? options.ConnectionString)
                .Validate(options => options.Workers > 0 && options.PollIntervalSeconds > 0
                    && options.ProcessTimeoutSeconds > 0 && options.TopPorts > 0
                    && options.TopPorts <= 65535 && !string.IsNullOrWhiteSpace(options.ConnectionString)
                    && !string.IsNullOrWhiteSpace(options.Executable), "Invalid Recon configuration")
                .ValidateOnStart();
            services.AddSingleton<INmapScanner, NmapScanner>();
            services.AddSingleton<IReconJobStore, SqlReconJobStore>();
            services.AddHostedService<ReconWorker>();
            services.AddOptions<ShodanOptions>()
                .Bind(_configuration.GetSection("Shodan"))
                .PostConfigure<IOptions<ReconOptions>>((options, recon) =>
                    options.ConnectionString = connectionString ?? options.ConnectionString ?? recon.Value.ConnectionString)
                .Validate(options => options.RequestIntervalSeconds > 0 && double.IsFinite(options.RequestIntervalSeconds)
                    && options.RequestTimeoutSeconds > 0 && options.RequestTimeoutSeconds <= int.MaxValue - 120
                    && options.PollIntervalSeconds > 0 && double.IsFinite(options.PollIntervalSeconds)
                    && options.RetryDelaySeconds > 0 && double.IsFinite(options.RetryDelaySeconds)
                    && options.MaxRetryDelaySeconds >= options.RetryDelaySeconds && double.IsFinite(options.MaxRetryDelaySeconds)
                    && !string.IsNullOrWhiteSpace(options.ConnectionString), "Invalid Shodan configuration")
                .ValidateOnStart();
            services.AddSingleton(provider =>
            {
                var options = provider.GetRequiredService<IOptions<ShodanOptions>>();
                // A dedicated client avoids logging a URL containing Shodan's query-string key.
                return new ShodanScanner(new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
                { Timeout = TimeSpan.FromSeconds(options.Value.RequestTimeoutSeconds) }, options);
            });
            services.AddHostedService(provider =>
            {
                var options = provider.GetRequiredService<IOptions<ShodanOptions>>();
                var store = new SqlReconJobStore(Options.Create(new ReconOptions
                {
                    ConnectionString = options.Value.ConnectionString,
                    ProcessTimeoutSeconds = options.Value.RequestTimeoutSeconds
                }), "Shodan");
                return new ShodanWorker(store, provider.GetRequiredService<ShodanScanner>(), options,
                    provider.GetRequiredService<ILogger<ShodanWorker>>());
            });
        }

        public void Configure(IApplicationBuilder app, ProfileResponder responder, ILogger<Startup> logger)
        {
            logger.LogInformation("Honeypot collector [github.com/chrispydizzle/MockacoHoneypot]");

            if (_configuration.GetValue<bool>("Honeypot:DisableRequestLogging"))
            {
                logger.LogWarning("Request logging is disabled. This is not recommended for production use.");
            }
            else
            {
                app.UseMiddleware<DatabaseLoggingMiddleware>();
            }

            app.Run(responder.InvokeAsync);
        }
    }
}