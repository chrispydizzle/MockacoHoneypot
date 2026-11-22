using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Attack
{
    /// <summary>
    /// Deeper reconnaissance: vulnerability scanning, CVE matching, OS detection,
    /// service enumeration beyond initial nmap/shodan scans.
    /// </summary>
    public sealed class ReconStrategy : IAttackStrategy
    {
        private readonly AttackClient _client;
        private readonly ILogger<ReconStrategy> _logger;

        public ReconStrategy(AttackClient client, ILogger<ReconStrategy> logger)
        {
            _client = client;
            _logger = logger;
        }

        public AttackType Type => AttackType.Recon;

        public async Task PrepareAsync(AttackContext context, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(context.Parameters))
            {
                context.Parameters = $"deeprecon={context.Service}&port={context.Port}";
            }
        }

        public async Task<AttackExecutionResult> ExecuteAsync(AttackContext context, CancellationToken cancellationToken)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                var findings = new List<string>();

                // Run vulnerability scan
                findings.Add(await RunVulnScanAsync(context, cancellationToken));

                // Run CVE matching
                findings.Add(await RunCveMatchingAsync(context, cancellationToken));

                // Run OS detection refinement
                findings.Add(await RunOsDetectionAsync(context, cancellationToken));

                sw.Stop();

                _logger.LogInformation(
                    "Deep recon on {Host}:{Port} ({Service}) found {Findings} issues ({Elapsed:F2}s)",
                    context.IpAddress, context.Port, context.Service,
                    findings.Count, sw.Elapsed.TotalSeconds);

                return new AttackExecutionResult
                {
                    Success = true,
                    Message = $"Deep recon complete: {findings.Count} findings",
                    Response = string.Join("\n", findings),
                    Elapsed = sw.Elapsed
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                _logger.LogError(ex, "Deep recon failed for {Host}:{Port}", context.IpAddress, context.Port);
                return new AttackExecutionResult
                {
                    Success = false,
                    Message = $"Deep recon failed on port {context.Port}",
                    ErrorMessage = ex.Message,
                    Elapsed = sw.Elapsed
                };
            }
        }

        private async Task<string> RunVulnScanAsync(AttackContext context, CancellationToken cancellationToken)
        {
            var response = await _client.LaunchAttackAsync(
                context.IpAddress,
                "VulnScan",
                "POST",
                $"/api/vulnscan/{context.Port}",
                $"service={context.Service}&version={context.Version}",
                cancellationToken);

            return $"VulnScan: {(response.Contains("\"success\":true") ? "PASS" : "FAIL")} - {response}";
        }

        private async Task<string> RunCveMatchingAsync(AttackContext context, CancellationToken cancellationToken)
        {
            var response = await _client.LaunchAttackAsync(
                context.IpAddress,
                "CveMatch",
                "POST",
                "/api/cvematch",
                $"service={context.Service}&version={context.Version}&port={context.Port}",
                cancellationToken);

            return $"CveMatch: {response}";
        }

        private async Task<string> RunOsDetectionAsync(AttackContext context, CancellationToken cancellationToken)
        {
            var response = await _client.LaunchAttackAsync(
                context.IpAddress,
                "OsDetect",
                "POST",
                "/api/osdetection",
                $"ip={context.IpAddress}&port={context.Port}&service={context.Service}",
                cancellationToken);

            return $"OsDetect: {response}";
        }
    }
}
