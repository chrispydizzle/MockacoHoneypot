using System;
using System.Threading;

namespace Mockaco.Recon
{
    public interface IReconFailureEvidence
    {
        ReconEvidence Evidence { get; }
    }

    public sealed class ReconScanException : InvalidOperationException, IReconFailureEvidence
    {
        public ReconEvidence Evidence { get; }

        public ReconScanException(string message, ReconEvidence evidence, Exception inner = null)
            : base(message, inner) => Evidence = evidence;
    }

    public sealed class ReconScanTimeoutException : TimeoutException, IReconFailureEvidence
    {
        public ReconEvidence Evidence { get; }

        public ReconScanTimeoutException(string message, ReconEvidence evidence)
            : base(message) => Evidence = evidence;
    }

    public sealed class ReconScanCanceledException : OperationCanceledException, IReconFailureEvidence
    {
        public ReconEvidence Evidence { get; }

        public ReconScanCanceledException(ReconEvidence evidence, CancellationToken cancellationToken)
            : base("Nmap scan was cancelled.", cancellationToken) => Evidence = evidence;
    }
}
