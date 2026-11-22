using Microsoft.Extensions.Logging;
using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Attack
{
    /// <summary>
    /// Port-level probes and version checks.
    /// Performs targeted port scanning, banner grabbing, and version detection.
    /// </summary>
    public sealed class PortStrategy : IAttackStrategy
    {
        private readonly ILogger<PortStrategy> _logger;

        public PortStrategy(ILogger<PortStrategy> logger)
        {
            _logger = logger;
        }

        public AttackType Type => AttackType.Port;

        public async Task PrepareAsync(AttackContext context, CancellationToken cancellationToken)
        {
            // Pre-flight: verify port is reachable
            var isReachable = await IsPortReachableAsync(context.Port, cancellationToken);
            if (!isReachable)
            {
                _logger.LogWarning("Port {Port} on {Host} may be filtered or closed", context.Port, context.IpAddress);
            }
        }

        public async Task<AttackExecutionResult> ExecuteAsync(AttackContext context, CancellationToken cancellationToken)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                // Perform targeted port probe
                var banner = await GrabBannerAsync(context, cancellationToken);
                var versionMatch = DetectVersion(context);

                sw.Stop();

                _logger.LogInformation(
                    "Port probe on {Host}:{Port} ({Service} v{Version}) returned banner of {BannerLength} bytes ({Elapsed:F2}s)",
                    context.IpAddress, context.Port, context.Service, context.Version,
                    banner?.Length ?? 0, sw.Elapsed.TotalSeconds);

                return new AttackExecutionResult
                {
                    Success = !string.IsNullOrWhiteSpace(banner),
                    Message = $"Port {context.Port} probe complete",
                    Response = banner ?? string.Empty,
                    Elapsed = sw.Elapsed
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                _logger.LogError(ex, "Port probe failed for {Host}:{Port}", context.IpAddress, context.Port);
                return new AttackExecutionResult
                {
                    Success = false,
                    Message = $"Port {context.Port} probe failed",
                    ErrorMessage = ex.Message,
                    Elapsed = sw.Elapsed
                };
            }
        }

        private async Task<string> GrabBannerAsync(AttackContext context, CancellationToken cancellationToken)
        {
            using var client = new TcpClient();
            try
            {
                await client.ConnectAsync(context.IpAddress, context.Port, cancellationToken);
                using var stream = client.GetStream();
                var buffer = new byte[1024];
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                return System.Text.Encoding.UTF8.GetString(buffer, 0, bytesRead);
            }
            catch
            {
                return null;
            }
        }

        private async Task<bool> IsPortReachableAsync(int port, CancellationToken cancellationToken)
        {
            using var client = new TcpClient();
            try
            {
                await client.ConnectAsync("127.0.0.1", port, cancellationToken);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private string DetectVersion(AttackContext context)
        {
            if (!string.IsNullOrWhiteSpace(context.Version))
                return context.Version;

            if (!string.IsNullOrWhiteSpace(context.Service))
                return context.Service;

            return "unknown";
        }
    }
}
