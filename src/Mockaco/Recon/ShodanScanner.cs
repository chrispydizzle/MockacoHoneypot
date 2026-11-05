using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Recon
{
    public sealed class ShodanLookupException : Exception
    {
        public bool Retryable { get; }
        public bool Pause { get; }
        public TimeSpan? RetryAfter { get; }

        public ShodanLookupException(string message, bool retryable = true, bool pause = false,
            TimeSpan? retryAfter = null) : base(message)
        {
            Retryable = retryable;
            Pause = pause;
            RetryAfter = retryAfter;
        }
    }

    public sealed class ShodanScanner : IDisposable
    {
        private readonly HttpClient _client;
        private readonly string _apiKey;

        public ShodanScanner(HttpClient client, IOptions<ShodanOptions> options)
        {
            _client = client;
            _apiKey = options.Value.ApiKey;
        }

        public async Task<ReconScan> ScanAsync(string target, CancellationToken cancellationToken)
        {
            if (!IPAddress.TryParse(target, out var address))
                throw new ArgumentException("Shodan lookup requires an IP address.", nameof(target));
            if (string.IsNullOrWhiteSpace(_apiKey))
                throw new ShodanLookupException("Shodan API key is not configured.", pause: true);
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            var uri = $"https://api.shodan.io/shodan/host/{Uri.EscapeDataString(address.ToString())}"
                + $"?key={Uri.EscapeDataString(_apiKey)}&history=false&minify=false";
            try
            {
                using var response = await _client.GetAsync(uri, cancellationToken);
                var status = (int)response.StatusCode;
                var retryAfter = response.Headers.RetryAfter?.Delta
                    ?? (response.Headers.RetryAfter?.Date - DateTimeOffset.UtcNow);
                if (retryAfter < TimeSpan.Zero) retryAfter = TimeSpan.Zero;
                if (status is 401 or 403)
                    throw new ShodanLookupException($"Shodan HTTP {status}: check API key and account permissions; restart to resume.",
                        pause: true);
                if (status == 429 || status == 408 || status >= 500)
                    throw new ShodanLookupException($"Shodan HTTP {status}; lookup will be retried.", retryAfter: retryAfter);
                if (status != 200 && status != 404)
                    throw new ShodanLookupException($"Shodan HTTP {status}; lookup was rejected.", retryable: false);
                var json = await response.Content.ReadAsStringAsync(cancellationToken);
                var evidence = new ReconEvidence(status, DateTime.UtcNow, json);
                using var document = JsonDocument.Parse(json);
                var root = document.RootElement;
                if (status == 404)
                {
                    if (Text(root, "error") != "No information available for that IP." && Text(root, "error") != "Invalid IP")
                        throw new ShodanLookupException($"Shodan returned an unexpected 404 response.{root}:{target}");
                    return new ReconScan(Array.Empty<string>(), Array.Empty<ReconPort>(), evidence);
                }
                if (!IPAddress.TryParse(Text(root, "ip_str"), out var returnedAddress) || !address.Equals(returnedAddress)
                    || !root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
                    throw new ShodanLookupException("Shodan returned an incomplete or mismatched host record.");

                var hostnames = new List<string>();
                if (root.TryGetProperty("hostnames", out var names) && names.ValueKind == JsonValueKind.Array)
                    foreach (var name in names.EnumerateArray())
                        if (name.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(name.GetString()))
                            hostnames.Add(name.GetString());
                var ports = new List<ReconPort>();
                foreach (var banner in data.EnumerateArray())
                {
                    if (banner.ValueKind != JsonValueKind.Object
                        || !banner.TryGetProperty("port", out var port) || !port.TryGetInt32(out var number)
                        || number is < 1 or > 65535)
                        throw new ShodanLookupException("Shodan returned an invalid service port.");
                    var transport = Text(banner, "transport");
                    if (transport is not ("tcp" or "udp"))
                        throw new ShodanLookupException("Shodan returned an invalid service transport.");
                    var module = banner.TryGetProperty("_shodan", out var metadata) ? Text(metadata, "module") : null;
                    if (module?.EndsWith("-" + transport, StringComparison.Ordinal) == true)
                        module = module[..^(transport.Length + 1)];
                    var service = string.Join(" ", new[] { module ?? "unknown", Text(banner, "product"), Text(banner, "version") }
                        .Where(value => !string.IsNullOrWhiteSpace(value)));
                    var text = Text(banner, "data");
                    if (!string.IsNullOrEmpty(text)) service += "\n" + text;
                    DateTime? observed = DateTime.TryParse(Text(banner, "timestamp"), CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var time) ? time : null;
                    ports.Add(new ReconPort(number, transport, service, observed));
                }
                return new ReconScan(hostnames.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(), ports, evidence);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new ShodanLookupException("Shodan request timed out; lookup will be retried.");
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException)
            {
                // HttpClient errors can contain the query-string API key.
                throw new ShodanLookupException("Shodan network request failed; lookup will be retried.");
            }
            catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException)
            {
                throw new ShodanLookupException("Shodan returned malformed host data; lookup will be retried.");
            }
        }

        private static string Text(JsonElement element, string property) =>
            element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value)
                && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

        public void Dispose() => _client.Dispose();
    }
}
