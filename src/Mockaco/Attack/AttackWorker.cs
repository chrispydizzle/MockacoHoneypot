using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Attack
{
    /// <summary>
    /// Background service that polls for hosts with recon findings and processes them through the attack pipeline.
    /// </summary>
    public sealed class AttackWorker : BackgroundService
    {
        private readonly IAttackEngine _engine;
        private readonly AttackOptions _options;
        private readonly ILogger<AttackWorker> _logger;

        public AttackWorker(IAttackEngine engine, IOptions<AttackOptions> options, ILogger<AttackWorker> logger)
        {
            _engine = engine;
            _options = options.Value;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Attack worker starting with {Workers} workers and {PollInterval}s poll interval",
                _options.Workers, _options.PollIntervalSeconds);

            while (!stoppingToken.IsCancellationRequested)
            {
                var tasks = new List<Task>();
                for (var i = 0; i < _options.Workers; i++)
                    tasks.Add(ProcessHostAsync(stoppingToken));

                await Task.WhenAll(tasks);

                if (stoppingToken.IsCancellationRequested)
                    return;

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(_options.PollIntervalSeconds), stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
            }
        }

        private async Task ProcessHostAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var outcome = await _engine.ProcessNextHostAsync(stoppingToken);

                if (!outcome.Processed)
                    return; // No more hosts to process this cycle

                _logger.LogInformation(
                    "Attack {Success} for host {HostId} ({IpAddress}), attack id {AttackId}",
                    outcome.Success == true ? "succeeded" : "completed with issues",
                    outcome.HostId, outcome.IpAddress, outcome.AttackId);
            }
        }
    }
}
