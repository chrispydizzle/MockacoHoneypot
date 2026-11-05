using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mockaco.Recon;
using Moq;
using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Mockaco.Tests.Recon
{
    public class ReconWorkerTest
    {
        [Fact]
        public async Task RecordsFailureAndContinuesToNextJob()
        {
            var first = new ReconJob(1, 1, "127.0.0.1", Guid.NewGuid());
            var second = new ReconJob(2, 2, "127.0.0.2", Guid.NewGuid());
            var jobs = new ConcurrentQueue<ReconJob>(new[] { first, second });
            var finished = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var store = new Mock<IReconJobStore>();
            store.Setup(s => s.ClaimAsync(It.IsAny<CancellationToken>()))
                .Returns(() => Task.FromResult(jobs.TryDequeue(out var job) ? job : null));
            store.Setup(s => s.FailAsync(first, It.IsAny<string>(), false, It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            store.Setup(s => s.CompleteAsync(second, It.IsAny<ReconScan>(), It.IsAny<CancellationToken>()))
                .Returns(() => { finished.TrySetResult(true); return Task.CompletedTask; });
            var scanner = new Mock<INmapScanner>();
            scanner.Setup(s => s.ScanAsync(first.Target, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new InvalidOperationException("Nmap failed"));
            scanner.Setup(s => s.ScanAsync(second.Target, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new ReconScan(Array.Empty<string>(), Array.Empty<ReconPort>()));
            using var worker = new ReconWorker(store.Object, scanner.Object,
                Options.Create(new ReconOptions { Workers = 1, PollIntervalSeconds = 1 }),
                NullLogger<ReconWorker>.Instance);
            try
            {
                await worker.StartAsync(CancellationToken.None);
                await finished.Task.WaitAsync(TimeSpan.FromSeconds(5));
            }
            finally { await worker.StopAsync(CancellationToken.None); }
            store.Verify(s => s.FailAsync(first, It.Is<string>(error => error.Contains("Nmap failed")),
                false, It.IsAny<CancellationToken>()), Times.Once);
            store.Verify(s => s.CompleteAsync(first, It.IsAny<ReconScan>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task RunsConfiguredConcurrencyAndReleasesJobsOnShutdown()
        {
            const int workers = 4;
            var jobs = new ConcurrentQueue<ReconJob>();
            for (int i = 0; i < workers; i++)
                jobs.Enqueue(new ReconJob(i, i, "127.0.0.1", Guid.NewGuid()));
            var allStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            int active = 0;
            var scanner = new Mock<INmapScanner>();
            scanner.Setup(s => s.ScanAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(async (string target, CancellationToken token) =>
                {
                    if (Interlocked.Increment(ref active) == workers) allStarted.TrySetResult(true);
                    try { await Task.Delay(Timeout.Infinite, token); }
                    finally { Interlocked.Decrement(ref active); }
                    return new ReconScan(Array.Empty<string>(), Array.Empty<ReconPort>());
                });
            var store = new Mock<IReconJobStore>();
            store.Setup(s => s.ClaimAsync(It.IsAny<CancellationToken>()))
                .Returns(() => Task.FromResult(jobs.TryDequeue(out var job) ? job : null));
            store.Setup(s => s.FailAsync(It.IsAny<ReconJob>(), It.IsAny<string>(), true, It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            using var worker = new ReconWorker(store.Object, scanner.Object,
                Options.Create(new ReconOptions { Workers = workers }), NullLogger<ReconWorker>.Instance);
            try
            {
                await worker.StartAsync(CancellationToken.None);
                await allStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
                Assert.Equal(workers, active);
            }
            finally
            {
                await worker.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));
            }
            Assert.Equal(0, active);
            store.Verify(s => s.FailAsync(It.IsAny<ReconJob>(), It.IsAny<string>(), true,
                It.IsAny<CancellationToken>()), Times.Exactly(workers));
            store.Verify(s => s.CompleteAsync(It.IsAny<ReconJob>(), It.IsAny<ReconScan>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }
    }
}
