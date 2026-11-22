using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Attack
{
    /// <summary>
    /// Core engine that orchestrates LLM research and strategy-based attack execution for hosts with findings.
    /// </summary>
    public sealed class AttackEngine : IAttackEngine
    {
        private readonly IAttackStore _store;
        private readonly AttackClient _client;
        private readonly AttackStrategyResolver _resolver;
        private readonly ILogger<AttackEngine> _logger;

        public AttackEngine(
            IAttackStore store,
            AttackClient client,
            AttackStrategyResolver resolver,
            ILogger<AttackEngine> logger)
        {
            _store = store;
            _client = client;
            _resolver = resolver;
            _logger = logger;
        }

        /// <summary>
        /// Picks the next host with findings, runs LLM research, and dispatches attacks through strategies.
        /// </summary>
        public async Task<AttackOutcome> ProcessNextHostAsync(CancellationToken cancellationToken)
        {
            var hosts = await _store.GetHostsWithFindingsAsync(1, cancellationToken);

            if (hosts.Count == 0)
                return new AttackOutcome(Processed: false, null, null, null, null);

            var host = hosts[0];
            _logger.LogInformation("Processing host {HostId} ({IpAddress}) with {Ports} ports and {Shodan} shodan records",
                host.HostId, host.IpAddress, host.PortCount, host.ShodanRecordCount);

            await _store.MarkResearchingAsync(host.HostId, cancellationToken);

            // 1. Run LLM research to identify findings and recommended attacks
            var researchResult = await RunResearchAsync(host, cancellationToken);

            // 2. Create the attack record
            var attackName = researchResult?.RecommendedAttacks
                ?.FirstOrDefault()?.AttackName ?? $"default_{host.IpAddress.Replace(".", "_")}";

            var researchType = researchResult?.RecommendedAttacks?.FirstOrDefault()?.Type ?? AttackType.Recon;
            var attackId = await _store.CreateAttackAsync(host.IpAddress, attackName, (int)researchType, cancellationToken);

            // 3. Save LLM findings to database
            if (researchResult?.Findings != null && researchResult.Findings.Count > 0)
            {
                var findings = researchResult.Findings.Select(f => new AttackFinding(
                    FindingId: 0,
                    AttackId: attackId,
                    FindingType: f.FindingType,
                    Severity: f.Severity,
                    Title: f.Title,
                    Description: f.Description,
                    Evidence: f.Evidence,
                    Exploitable: f.Exploitable
                )).ToList();

                await _store.SaveFindingsAsync(attackId, findings, cancellationToken);
            }

            // 4. Dispatch each recommended attack through its strategy
            var success = await DispatchStrategicAttacksAsync(host, researchResult, attackId, cancellationToken);

            await _store.SaveAttackResultAsync(attackId, success, researchResult?.ToString() ?? "", null, cancellationToken);

            return new AttackOutcome(
                Processed: true,
                HostId: host.HostId,
                IpAddress: host.IpAddress,
                AttackId: attackId,
                Success: success);
        }

        /// <summary>
        /// Sends host findings to the LLM for research.
        /// </summary>
        private async Task<LlmResearchResponse> RunResearchAsync(HostWithFindings host, CancellationToken cancellationToken)
        {
            var ports = !string.IsNullOrWhiteSpace(host.PortDetails)
                ? new List<string>(host.PortDetails.Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries))
                : new List<string>();

            var shodanServices = new List<string>();
            if (!string.IsNullOrWhiteSpace(host.ShodanData))
            {
                try
                {
                    using var doc = JsonDocument.Parse(host.ShodanData);
                    var root = doc.RootElement;
                    if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var banner in data.EnumerateArray())
                        {
                            var service = banner.TryGetProperty("product", out var product) && product.ValueKind == JsonValueKind.String
                                ? product.GetString()
                                : banner.TryGetProperty("service", out var svc) && svc.ValueKind == JsonValueKind.String
                                    ? svc.GetString()
                                    : "unknown";
                            var port = banner.TryGetProperty("port", out var portProp) && portProp.ValueKind == JsonValueKind.Number
                                ? portProp.GetInt32().ToString()
                                : null;
                            if (!string.IsNullOrEmpty(port))
                                service += $":{port}";
                            shodanServices.Add(service);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not parse Shodan data for {Host}", host.IpAddress);
                    shodanServices.Add(host.ShodanData);
                }
            }

            return await _client.ResearchAsync(host.IpAddress, ports, shodanServices, cancellationToken);
        }

        /// <summary>
        /// Dispatches each recommended attack through the appropriate IAttackStrategy.
        /// Falls back to a generic LLM call if no matching strategy is found.
        /// </summary>
        private async Task<bool> DispatchStrategicAttacksAsync(HostWithFindings host, LlmResearchResponse research, long attackId, CancellationToken cancellationToken)
        {
            var allSuccess = true;

            if (research?.RecommendedAttacks != null)
            {
                foreach (var attack in research.RecommendedAttacks)
                {
                    _logger.LogInformation(
                        "Dispatching {AttackType} attack '{AttackName}' against {Host}",
                        attack.Type, attack.AttackName, host.IpAddress);

                    try
                    {
                        var strategy = _resolver.GetStrategyByName(attack.AttackName);

                        // Build the context from the host's recon data
                        var context = BuildAttackContext(host, attack);
                        await strategy.PrepareAsync(context, cancellationToken);
                        var result = await strategy.ExecuteAsync(context, cancellationToken);

                        // Save strategy-level result
                        await _store.SaveStrategyResultAsync(attackId, attack.AttackName, result.Success, result.Response, result.ErrorMessage, cancellationToken);

                        if (!result.Success)
                        {
                            _logger.LogWarning(
                                "Strategy {StrategyType} returned failure for {AttackName} on {Host}: {Message}",
                                strategy.Type, attack.AttackName, host.IpAddress, result.Message);
                            allSuccess = false;
                        }

                        _logger.LogInformation(
                            "Strategy {StrategyType} completed '{AttackName}' for {Host} in {Elapsed:F2}s: {Message}",
                            strategy.Type, attack.AttackName, host.IpAddress, result.Elapsed.TotalSeconds, result.Message);
                    }
                    catch (InvalidOperationException ex) when (ex.Message.Contains("No strategy registered"))
                    {
                        // Fallback: dispatch through the generic LLM client
                        _logger.LogInformation(
                            "No strategy for '{AttackName}', falling back to LLM dispatch",
                            attack.AttackName);

                        var result = await _client.LaunchAttackAsync(
                            host.IpAddress, attack.AttackName,
                            attack.Method ?? "GET", attack.Target ?? "/",
                            attack.Parameters, cancellationToken);

                        var success = result.Contains("\"success\":true");
                        if (!success) allSuccess = false;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Strategy execution failed for '{AttackName}' on {Host}", attack.AttackName, host.IpAddress);
                        allSuccess = false;
                    }
                }
            }
            else
            {
                // No recommendations: run a default Recon strategy
                _logger.LogInformation("No LLM recommendations; running default Recon strategy for {Host}", host.IpAddress);

                var defaultContext = BuildAttackContext(host, new LlmRecommendedAttack("default", AttackType.Recon, "GET", "/", ""));
                var reconStrategy = _resolver.GetStrategy(AttackType.Recon);
                await reconStrategy.PrepareAsync(defaultContext, cancellationToken);
                var result = await reconStrategy.ExecuteAsync(defaultContext, cancellationToken);

                if (!result.Success) allSuccess = false;
            }

            return allSuccess;
        }

        /// <summary>
        /// Builds an AttackContext from host recon data and an attack recommendation.
        /// </summary>
        private static AttackContext BuildAttackContext(HostWithFindings host, LlmRecommendedAttack attack)
        {
            var context = new AttackContext
            {
                IpAddress = host.IpAddress,
                Port = 0,
                Protocol = "tcp",
                Service = !string.IsNullOrWhiteSpace(attack.Parameters) && attack.Parameters.Contains("service=")
                    ? attack.Parameters.Split('&').FirstOrDefault(p => p.StartsWith("service="))?.Split('=')[1]
                    : "unknown",
                Version = "unknown",
                Vulnerability = attack.AttackName,
                Parameters = attack.Parameters
            };

            return context;
        }
    }

    /// <summary>
    /// Interface for the attack engine (for DI and testing).
    /// </summary>
    public interface IAttackEngine
    {
        Task<AttackOutcome> ProcessNextHostAsync(CancellationToken cancellationToken);
    }

    /// <summary>
    /// Outcome of processing a single host.
    /// </summary>
    public sealed record AttackOutcome(bool Processed, long? HostId, string IpAddress, long? AttackId, bool? Success);
}
