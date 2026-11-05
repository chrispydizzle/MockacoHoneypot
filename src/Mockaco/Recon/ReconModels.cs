using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Recon
{
    public sealed record ReconJob(long HostJobId, long HostId, string Target, Guid LeaseToken);
    public sealed record ReconPort(int Number, string Protocol, string Detail, DateTime? ObservedAtUtc = null);
    public sealed record ReconEvidence(int StatusCode, DateTime RetrievedAtUtc, string ResponseJson);
    public sealed record ReconScan(IReadOnlyList<string> Hostnames, IReadOnlyList<ReconPort> Ports,
        ReconEvidence Evidence = null);

    public interface INmapScanner
    {
        Task<ReconScan> ScanAsync(string target, CancellationToken cancellationToken);
    }

    public interface IReconJobStore
    {
        Task<ReconJob> ClaimAsync(CancellationToken cancellationToken);
        Task CompleteAsync(ReconJob job, ReconScan scan, CancellationToken cancellationToken);
        Task FailAsync(ReconJob job, string error, bool cancelled, CancellationToken cancellationToken);
    }
}
