using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Attack
{
    /// <summary>
    /// Distinct attack categories the engine can dispatch.
    /// Each type maps to a different execution path and tooling.
    /// </summary>
    public enum AttackType
    {
        /// <summary>
        /// CVE-based or service-specific exploit execution.
        /// </summary>
        Exploit = 0,

        /// <summary>
        /// Direct service interaction (HTTP, SSH, SMB, FTP, etc.).
        /// </summary>
        Service = 1,

        /// <summary>
        /// Port-level probes and version checks.
        /// </summary>
        Port = 2,

        /// <summary>
        /// Credential-based attacks (brute force, pass-the-hash, etc.).
        /// </summary>
        Credential = 3,

        /// <summary>
        /// Web application attacks (SQLi, XSS, RCE, etc.).
        /// </summary>
        Web = 4,

        /// <summary>
        /// Network pivoting and lateral movement.
        /// </summary>
        LateralMovement = 5,

        /// <summary>
        /// Deeper reconnaissance (vuln scanning, CVE matching, OS detection).
        /// </summary>
        Recon = 6
    }

    /// <summary>
    /// Context passed to an attack strategy during execution.
    /// </summary>
    public sealed class AttackContext
    {
        public string IpAddress { get; set; }
        public long HostId { get; set; }
        public int Port { get; set; }
        public string Protocol { get; set; }
        public string Service { get; set; }
        public string Version { get; set; }
        public string Vulnerability { get; set; }
        public string Parameters { get; set; }
        public string Payload { get; set; }
    }

    /// <summary>
    /// Result of an attack strategy execution.
    /// </summary>
    public sealed class AttackExecutionResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string Response { get; set; }
        public string ErrorMessage { get; set; }
        public TimeSpan Elapsed { get; set; }
    }

    /// <summary>
    /// Strategy interface for attack types.
    /// Each implementation handles one AttackType.
    /// </summary>
    public interface IAttackStrategy
    {
        /// <summary>
        /// The attack type this strategy handles.
        /// </summary>
        AttackType Type { get; }

        /// <summary>
        /// Execute the attack against the target.
        /// </summary>
        Task<AttackExecutionResult> ExecuteAsync(AttackContext context, CancellationToken cancellationToken);

        /// <summary>
        /// Prepare the context before execution (resolve ports, fetch payloads, etc.).
        /// </summary>
        Task PrepareAsync(AttackContext context, CancellationToken cancellationToken);
    }

    /// <summary>
    /// Resolves the appropriate IAttackStrategy for a given attack name or type.
    /// </summary>
    public class AttackStrategyResolver
    {
        private readonly IAttackStrategy[] _strategies;

        public AttackStrategyResolver(IAttackStrategy[] strategies)
        {
            _strategies = strategies ?? Array.Empty<IAttackStrategy>();
        }

        /// <summary>
        /// Gets the strategy for a specific attack type.
        /// </summary>
        public IAttackStrategy GetStrategy(AttackType type)
        {
            return _strategies.FirstOrDefault(s => s.Type == type)
                ?? throw new InvalidOperationException($"No strategy registered for attack type {type}.");
        }

        /// <summary>
        /// Gets the strategy for a specific attack name (by convention).
        /// </summary>
        public IAttackStrategy GetStrategyByName(string attackName)
        {
            if (string.IsNullOrWhiteSpace(attackName))
                return _strategies[0];

            var nameLower = attackName.ToLowerInvariant();

            foreach (var strategy in _strategies)
            {
                if (strategy.Type.ToString().Equals(nameLower, StringComparison.OrdinalIgnoreCase))
                    return strategy;
            }

            // Fallback: match by keyword
            if (nameLower.Contains("exploit")) return GetStrategy(AttackType.Exploit);
            if (nameLower.Contains("service")) return GetStrategy(AttackType.Service);
            if (nameLower.Contains("port")) return GetStrategy(AttackType.Port);
            if (nameLower.Contains("credential") || nameLower.Contains("brute") || nameLower.Contains("pass")) return GetStrategy(AttackType.Credential);
            if (nameLower.Contains("web") || nameLower.Contains("http")) return GetStrategy(AttackType.Web);
            if (nameLower.Contains("lateral") || nameLower.Contains("piv")) return GetStrategy(AttackType.LateralMovement);
            if (nameLower.Contains("recon")) return GetStrategy(AttackType.Recon);

            return _strategies[0]; // Default fallback
        }
    }
}
