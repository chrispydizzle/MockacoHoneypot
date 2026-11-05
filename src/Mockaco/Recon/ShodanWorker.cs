using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Recon
{
    public sealed class ShodanWorker(IReconJobStore store, ShodanScanner scanner,
        IOptions<ShodanOptions> options, ILogger<ShodanWorker> logger) : BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var settings = options.Value;
            if (string.IsNullOrWhiteSpace(settings.ApiKey))
            {
                logger.LogInformation("Shodan lookup is disabled; no API key configured.");
                return;
            }
            var backoff = settings.RetryDelaySeconds;
            while (!stoppingToken.IsCancellationRequested)
            {
                ReconJob job = null;
                var delay = TimeSpan.FromSeconds(settings.RequestIntervalSeconds);
                var pause = false;
                try
                {
                    job = await store.ClaimAsync(stoppingToken);
                    if (job == null) delay = TimeSpan.FromSeconds(settings.PollIntervalSeconds);
                    else
                    {
                        var result = await scanner.ScanAsync(job.Target, stoppingToken);
                        await store.CompleteAsync(job, result, stoppingToken);
                        backoff = settings.RetryDelaySeconds;
                        logger.LogInformation("Shodan lookup {JobId} for {Target} completed: HTTP {Status}, {Services} service records",
                            job.HostJobId, job.Target, result.Evidence.StatusCode, result.Ports.Count);
                    }
                }
                catch (Exception exception)
                {
                    var cancelled = exception is OperationCanceledException && stoppingToken.IsCancellationRequested;
                    var lookup = exception as ShodanLookupException;
                    var retry = cancelled || lookup?.Retryable == true || job == null;
                    pause = lookup?.Pause == true;
                    if (!cancelled)
                        logger.LogWarning("Shodan lookup {JobId}: {Error}", job?.HostJobId, exception.Message);
                    if (job != null)
                    {
                        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                        try { await store.FailAsync(job, exception.Message, retry, cleanup.Token); }
                        catch (Exception failure)
                        {
                            logger.LogError(failure, "Could not release Shodan job {JobId}; its lease will expire", job.HostJobId);
                        }
                    }
                    if (stoppingToken.IsCancellationRequested) return;
                    if (retry)
                    {
                        delay = TimeSpan.FromSeconds(Math.Max(settings.RequestIntervalSeconds, backoff));
                        if (lookup?.RetryAfter is { } retryAfter && retryAfter > delay) delay = retryAfter;
                        backoff = Math.Min(backoff * 2, settings.MaxRetryDelaySeconds);
                    }
                }
                try { await Task.Delay(pause ? Timeout.InfiniteTimeSpan : delay, stoppingToken); }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
            }
        }
    }
}
