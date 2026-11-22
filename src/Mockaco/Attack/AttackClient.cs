using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Attack
{
    /// <summary>
    /// HTTP client for communicating with the local LLM server at 192.168.1.3.
    /// </summary>
    public sealed class AttackClient : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly AttackOptions _options;
        private readonly ILogger<AttackClient> _logger;
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        };

        public AttackClient(IOptions<AttackOptions> options, ILogger<AttackClient> logger)
        {
            _options = options.Value;
            _logger = logger;
            _httpClient = new HttpClient(new HttpClientHandler { AllowAutoRedirect = true })
            {
                BaseAddress = new Uri(_options.LlmBaseUrl.TrimEnd('/')),
                Timeout = TimeSpan.FromSeconds(_options.ResearchTimeoutSeconds)
            };
        }

        /// <summary>
        /// Sends scan findings to the LLM for research and returns structured findings plus recommended attacks.
        /// </summary>
        public async Task<LlmResearchResponse> ResearchAsync(
            string ipAddress,
            IReadOnlyList<string> ports,
            IReadOnlyList<string> shodanServices,
            CancellationToken cancellationToken)
        {
            var request = new
            {
                model = _options.LlmModel,
                temperature = _options.LlmTemperature,
                messages = new[]
                {
                    new { role = "system", content = _options.SystemPrompt },
                    new { role = "user", content = BuildResearchPrompt(ipAddress, ports, shodanServices) }
                },
                stream = false,
                max_tokens = 4096
            };

            var json = JsonSerializer.Serialize(request, JsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var uri = new Uri(_httpClient.BaseAddress, "v1/chat/completions");
            _logger.LogDebug("LLM research request to {Uri} for host {Host} model {Model}", uri, ipAddress, _options.LlmModel);
            _logger.LogDebug("LLM research request body: {Body}", json);

            try
            {
                var response = await _httpClient.PostAsync(uri, content, cancellationToken);
                var raw = await response.Content.ReadAsStringAsync(cancellationToken);

                _logger.LogDebug("LLM research response [{StatusCode}] (content-type: {ContentType}, length: {Length}): {Response}",
                    response.StatusCode, response.Content.Headers.ContentType?.ToString() ?? "(none)", raw.Length, raw);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("LLM research returned {StatusCode}: {Content}", response.StatusCode, raw);
                    throw new HttpRequestException($"LLM research returned {response.StatusCode}: {raw}");
                }

                var result = ParseResearchResponse(raw);

                _logger.LogInformation(
                    "LLM research completed for {Host}: {Findings} findings, {Attacks} recommended attacks",
                    ipAddress, result.Findings.Count, result.RecommendedAttacks.Count);

                return result;
            }
            catch (TaskCanceledException)
            {
                _logger.LogWarning(
                    "LLM research timed out for {Host} after {Timeout}s",
                    ipAddress, _options.ResearchTimeoutSeconds);
                return new LlmResearchResponse(Array.Empty<LlmFinding>(), Array.Empty<LlmRecommendedAttack>());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "LLM research failed for {Host}", ipAddress);
                throw;
            }
        }

        /// <summary>
        /// Launches a specific attack via the LLM and returns the result.
        /// </summary>
        public async Task<string> LaunchAttackAsync(
            string ipAddress,
            string attackName,
            string method,
            string target,
            string parameters,
            CancellationToken cancellationToken)
        {
            var prompt = BuildAttackCommandPrompt(ipAddress, attackName, method, target, parameters);

            var request = new
            {
                model = _options.LlmModel,
                temperature = 0.2,
                system = "Execute the attack. Return a JSON result with success, response body, and error fields.",
                prompt,
                stream = false,
                max_tokens = 2048
            };

            var json = JsonSerializer.Serialize(request, JsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var uri = $"{_httpClient.BaseAddress}/v1/chat/completions";

            try
            {
                var response = await _httpClient.PostAsync(uri, content, cancellationToken);
                response.EnsureSuccessStatusCode();

                var raw = await response.Content.ReadAsStringAsync(cancellationToken);
                var parsed = ParseAttackResponse(raw);

                _logger.LogInformation(
                    "Attack {AttackName} completed for {Host}: {Success}",
                    attackName, ipAddress, parsed.Contains("\"success\":true"));

                return parsed;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Attack {AttackName} failed for {Host}", attackName, ipAddress);
                return $"{{\"success\":false,\"error\":\"{ex.Message}\"}}";
            }
        }

        private string BuildResearchPrompt(string ipAddress, IReadOnlyList<string> ports, IReadOnlyList<string> shodanServices)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Research the host {ipAddress} and identify vulnerabilities, CVEs, and misconfigurations.");
            sb.AppendLine();

            if (ports.Count > 0)
            {
                sb.AppendLine("## Nmap Findings:");
                foreach (var port in ports)
                    sb.AppendLine($"- {port}");
                sb.AppendLine();
            }

            if (shodanServices.Count > 0)
            {
                sb.AppendLine("## Shodan Findings:");
                foreach (var svc in shodanServices)
                    sb.AppendLine($"- {svc}");
                sb.AppendLine();
            }

            sb.AppendLine("Return a structured JSON response with 'findings' and 'recommended_attacks' arrays.");
            sb.AppendLine("Each finding should include: type, severity (critical/high/medium/low), title, description, evidence, and exploitable.");
            sb.AppendLine("Each recommended attack should include: attack_name, method, target, parameters.");

            return sb.ToString();
        }

        private string BuildAttackCommandPrompt(string ipAddress, string attackName, string method, string target, string parameters)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Launch the '{attackName}' attack against {ipAddress}.");
            sb.AppendLine($"HTTP {method} {target}");
            if (!string.IsNullOrWhiteSpace(parameters))
                sb.AppendLine($"Parameters: {parameters}");
            sb.AppendLine();
            sb.AppendLine("Execute the attack and return a JSON result with: success (bool), response (string body), error (string message).");

            return sb.ToString();
        }

        private LlmResearchResponse ParseResearchResponse(string raw)
        {
            JsonDocument contentDoc;

            try
            {
                using var doc = JsonDocument.Parse(raw);
                var root = doc.RootElement;

                // Look for content in choices[0].message.content
                var content = string.Empty;
                var reasoning = string.Empty;

                if (root.TryGetProperty("choices", out var choices) && choices.GetArrayLength() > 0)
                {
                    var message = choices[0].GetProperty("message");
                    if (message.TryGetProperty("content", out var contentProp) && contentProp.ValueKind == JsonValueKind.String)
                    {
                        content = contentProp.GetString() ?? string.Empty;
                    }
                    if (message.TryGetProperty("reasoning", out var reasoningProp) && reasoningProp.ValueKind == JsonValueKind.String)
                    {
                        reasoning = reasoningProp.GetString() ?? string.Empty;
                    }
                }

                // If content is empty (reasoning-based models), extract embedded JSON from reasoning.
                // The reasoning field may contain free-form text followed by a { ... } JSON block.
                if (string.IsNullOrWhiteSpace(content) && !string.IsNullOrWhiteSpace(reasoning))
                {
                    var lastBrace = reasoning.LastIndexOf('}');
                    if (lastBrace > 0)
                    {
                        var firstBrace = reasoning.LastIndexOf('{', lastBrace);
                        if (firstBrace >= 0)
                        {
                            var jsonText = reasoning.Substring(firstBrace, lastBrace - firstBrace + 1);
                            try
                            {
                                contentDoc = JsonDocument.Parse(jsonText);
                                // return ExtractFindingsAndAttacks(contentDoc);
                            }
                            catch
                            {
                                // Fall through to the standard parse below
                            }
                        }
                    }
                }

                contentDoc = JsonDocument.Parse(string.IsNullOrEmpty(content) ? raw : content);
            }
            catch
            {
                // If LLM returns text instead of JSON, treat as a single finding
                contentDoc = JsonDocument.Parse(raw);
            }

            var contentRoot = contentDoc.RootElement;
            var findings = new List<LlmFinding>();
            var attacks = new List<LlmRecommendedAttack>();

            if (contentRoot.TryGetProperty("findings", out var findingsArr) && findingsArr.ValueKind == JsonValueKind.Array)
            {
                foreach (var f in findingsArr.EnumerateArray())
                    findings.Add(new LlmFinding(
                        Text(f, "type"),
                        Text(f, "severity"),
                        Text(f, "title"),
                        Text(f, "description"),
                        Text(f, "evidence"),
                        f.TryGetProperty("exploitable", out var exp) && exp.GetBoolean()));
            }

            if (contentRoot.TryGetProperty("recommended_attacks", out var attacksArr) && attacksArr.ValueKind == JsonValueKind.Array)
            {
                foreach (var a in attacksArr.EnumerateArray())
                    attacks.Add(new LlmRecommendedAttack(
                        Text(a, "attack_name"),
                        AttackType.Exploit,
                        Text(a, "method"),
                        Text(a, "target"),
                        Text(a, "parameters")));
            }

            return new LlmResearchResponse(findings, attacks);
        }

        private string ParseAttackResponse(string raw)
        {
            try
            {
                using var doc = JsonDocument.Parse(raw);
                var root = doc.RootElement;
                return root.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString() ?? raw;
            }
            catch
            {
                return raw;
            }
        }

        private static string Text(JsonElement element, string property) =>
            element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value)
                && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

        public void Dispose() => _httpClient.Dispose();
    }
}
