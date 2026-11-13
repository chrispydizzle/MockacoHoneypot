using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Capture
{
    public sealed record CapturedRequest(string SourceAddress, string TargetHost, string Target, string Method,
        string QueryString, byte[] Body, string ContentType);

    public interface IRequestLog
    {
        Task WriteAsync(CapturedRequest request, CancellationToken cancellationToken);
    }
}
