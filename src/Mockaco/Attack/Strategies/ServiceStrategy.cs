using Microsoft.Extensions.Logging;
using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Attack
{
    /// <summary>
    /// Direct service interaction attacks (HTTP, SSH, SMB, FTP, etc.).
    /// Sends targeted requests to specific services based on recon data.
    /// </summary>
    public sealed class ServiceStrategy : IAttackStrategy
    {
        private readonly ILogger<ServiceStrategy> _logger;
        private static readonly HttpClient ServiceClient = new();

        public ServiceStrategy(ILogger<ServiceStrategy> logger)
        {
            _logger = logger;
        }

        public AttackType Type => AttackType.Service;

        public async Task PrepareAsync(AttackContext context, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(context.Parameters))
            {
                context.Parameters = $"service={context.Service}&port={context.Port}";
            }
        }

        public async Task<AttackExecutionResult> ExecuteAsync(AttackContext context, CancellationToken cancellationToken)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                var uri = GetServiceUri(context);
                var request = new HttpRequestMessage(HttpMethod.Post, uri)
                {
                    Content = new StringContent(context.Parameters, System.Text.Encoding.UTF8, "application/x-www-form-urlencoded")
                };

                using var response = await ServiceClient.SendAsync(request, cancellationToken);
                var content = await response.Content.ReadAsStringAsync(cancellationToken);

                sw.Stop();

                _logger.LogInformation(
                    "Service interaction {Verb} {Host}:{Port} ({Service}) returned {StatusCode} ({Elapsed:F2}s)",
                    request.Method, context.IpAddress, context.Port, context.Service,
                    (int)response.StatusCode, sw.Elapsed.TotalSeconds);

                return new AttackExecutionResult
                {
                    Success = response.IsSuccessStatusCode,
                    Message = $"{context.Service} interaction successful",
                    Response = content,
                    Elapsed = sw.Elapsed
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                _logger.LogError(ex, "Service interaction failed for {Host}:{Port}/{Service}", context.IpAddress, context.Port, context.Service);
                return new AttackExecutionResult
                {
                    Success = false,
                    Message = $"Service interaction failed on port {context.Port}",
                    ErrorMessage = ex.Message,
                    Elapsed = sw.Elapsed
                };
            }
        }

        private string GetServiceUri(AttackContext context)
        {
            var scheme = context.Protocol?.ToLowerInvariant() switch
            {
                "https" or "http" => context.Protocol.ToLowerInvariant(),
                "ssh" => "ssh",
                "ftp" => "ftp",
                "smb" => "smb",
                _ => "http"
            };

            return $"http://{context.IpAddress}:{context.Port}/{context.Service.ToLowerInvariant()}";
        }
    }
}
