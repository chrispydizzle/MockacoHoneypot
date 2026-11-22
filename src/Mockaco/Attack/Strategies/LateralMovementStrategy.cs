using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Attack
{
    /// <summary>
    /// Network pivoting and lateral movement.
    /// Exploits identified services to move laterally across the network.
    /// </summary>
    public sealed class LateralMovementStrategy : IAttackStrategy
    {
        private readonly AttackClient _client;
        private readonly ILogger<LateralMovementStrategy> _logger;

        public LateralMovementStrategy(AttackClient client, ILogger<LateralMovementStrategy> logger)
        {
            _client = client;
            _logger = logger;
        }

        public AttackType Type => AttackType.LateralMovement;

        public async Task PrepareAsync(AttackContext context, CancellationToken cancellationToken)
        {
            // Identify nearby hosts and available pivoting services
            if (string.IsNullOrWhiteSpace(context.Parameters))
            {
                context.Parameters = $"pivot={context.Service}&target={context.IpAddress}";
            }
        }

        public async Task<AttackExecutionResult> ExecuteAsync(AttackContext context, CancellationToken cancellationToken)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                var pivotTargets = await DiscoverPivotTargetsAsync(context, cancellationToken);
                var pivotResults = new List<bool>();

                foreach (var target in pivotTargets)
                {
                    try
                    {
                        var response = await _client.LaunchAttackAsync(
                            context.IpAddress,
                            "LateralPivot",
                            "POST",
                            $"/api/pivot/{target.Ip}:{target.Port}",
                            $"from={context.IpAddress}&to={target.Ip}&method={context.Service}",
                            cancellationToken);

                        pivotResults.Add(response.Contains("\"success\":true"));
                    }
                    catch
                    {
                        pivotResults.Add(false);
                    }
                }

                sw.Stop();
                var success = pivotResults.TrueForAll(r => r) || pivotResults.Any(r => r);
                var pivotsSucceeded = pivotResults.Count();

                _logger.LogInformation(
                    "Lateral movement from {Host}:{Port} reached {Pivots}/{Targets} targets ({Elapsed:F2}s)",
                    context.IpAddress, context.Port,
                    pivotsSucceeded, pivotResults.Count(), sw.Elapsed.TotalSeconds);

                return new AttackExecutionResult
                {
                    Success = success,
                    Message = $"{pivotsSucceeded}/{pivotResults.Count} lateral pivots succeeded",
                    Response = string.Join("\n", pivotResults),
                    Elapsed = sw.Elapsed
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                _logger.LogError(ex, "Lateral movement failed from {Host}:{Port}", context.IpAddress, context.Port);
                return new AttackExecutionResult
                {
                    Success = false,
                    Message = $"Lateral movement failed on port {context.Port}",
                    ErrorMessage = ex.Message,
                    Elapsed = sw.Elapsed
                };
            }
        }

        private async Task<List<(string Ip, int Port)>> DiscoverPivotTargetsAsync(
            AttackContext context, CancellationToken cancellationToken)
        {
            // For now, use a simple heuristic: scan common ports on the same subnet
            var baseIp = context.IpAddress;
            var lastOctet = baseIp.Split('.')[^1];

            var targets = new List<(string Ip, int Port)>();

            // Discover nearby hosts
            for (var i = 1; i <= 5; i++)
            {
                var candidate = $"{baseIp.Split('.')[0]}.{baseIp.Split('.')[1]}.{baseIp.Split('.')[2]}.{i}";
                if (candidate != baseIp)
                {
                    targets.Add((candidate, context.Port));
                }
            }

            return targets;
        }
    }
}
