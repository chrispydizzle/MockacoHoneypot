using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Recon
{
    public sealed class ReconWorker : BackgroundService
    {
        private readonly IReconJobStore _store;
        private readonly INmapScanner _scanner;
        private readonly ReconOptions _options;
        private readonly ILogger<ReconWorker> _logger;

        public ReconWorker(IReconJobStore store, INmapScanner scanner,
            IOptions<ReconOptions> options, ILogger<ReconWorker> logger)
        {
            _store = store;
            _scanner = scanner;
            _options = options.Value;
            _logger = logger;
        }

        protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
            Task.WhenAll(Enumerable.Range(0, _options.Workers).Select(_ => RunWorkerAsync(stoppingToken)));

        private async Task RunWorkerAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                ReconJob job = null;
                try
                {
                    job = await _store.ClaimAsync(stoppingToken);
                    if (job == null)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(_options.PollIntervalSeconds), stoppingToken);
                        continue;
                    }
                    var started = System.Diagnostics.Stopwatch.StartNew();
                    var result = await _scanner.ScanAsync(job.Target, stoppingToken);
                    await _store.CompleteAsync(job, result, stoppingToken);
                    _logger.LogInformation("Recon job {JobId} for {Target} completed in {Seconds:F2}s with {Ports} open ports",
                        job.HostJobId, job.Target, started.Elapsed.TotalSeconds, result.Ports.Count);
                }
                catch (Exception exception)
                {
                    var cancelled = exception is OperationCanceledException && stoppingToken.IsCancellationRequested;
                    if (!cancelled)
                        _logger.LogError(exception, "Recon job {JobId} failed", job?.HostJobId);
                    if (job != null)
                    {
                        using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                        try
                        {
                            await _store.FailAsync(job, exception.ToString(), cancelled, cleanup.Token);
                        }
                        catch (Exception failure)
                        {
                            _logger.LogError(failure, "Could not release recon job {JobId}; its lease will expire", job.HostJobId);
                        }
                    }
                    if (stoppingToken.IsCancellationRequested) return;
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(_options.PollIntervalSeconds), stoppingToken);
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { return; }
                }
            }
        }
    }
}
