using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Mockaco.Recon;
using Moq;
using System;
using System.Net;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Mockaco.Tests.Recon
{
    public class ShodanWorkerTest
    {
        [Fact]
        public async Task WithoutKeyDoesNotClaimOrSend()
        {
            var store = new Mock<IReconJobStore>(MockBehavior.Strict);
            using var client = ShodanScannerTest.Client((_, _) => throw new Exception("Unexpected API call"));
            using var worker = new ShodanWorker(store.Object, ShodanScannerTest.Scanner(client),
                Options.Create(new ShodanOptions()), NullLogger<ShodanWorker>.Instance);
            await worker.StartAsync(CancellationToken.None);
            await worker.ExecuteTask.WaitAsync(TimeSpan.FromSeconds(3));
            store.VerifyNoOtherCalls();
        }

        [Theory]
        [InlineData(429)]
        [InlineData(403)]
        public async Task ReleasesBeforeBackoffOrAuthenticationPauseAndStopsPromptly(int status)
        {
            var job = new ReconJob(1, 1, "192.0.2.1", Guid.NewGuid());
            var released = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var store = new Mock<IReconJobStore>(MockBehavior.Strict);
            store.Setup(s => s.ClaimAsync(It.IsAny<CancellationToken>())).ReturnsAsync(job);
            store.Setup(s => s.FailAsync(job, It.IsAny<string>(), true, It.IsAny<CancellationToken>()))
                .Returns(() => { released.TrySetResult(true); return Task.CompletedTask; });
            using var client = ShodanScannerTest.Client((_, _) =>
            {
                var response = ShodanScannerTest.Response((HttpStatusCode)status, "{}");
                response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMinutes(10));
                return Task.FromResult(response);
            });
            using var worker = Worker(store.Object, ShodanScannerTest.Scanner(client));
            try
            {
                await worker.StartAsync(CancellationToken.None);
                await released.Task.WaitAsync(TimeSpan.FromSeconds(3));
                await Task.Delay(80);
                store.Verify(s => s.ClaimAsync(It.IsAny<CancellationToken>()), Times.Once);
                store.Verify(s => s.CompleteAsync(It.IsAny<ReconJob>(), It.IsAny<ReconScan>(),
                    It.IsAny<CancellationToken>()), Times.Never);
            }
            finally { await worker.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(3)); }
        }

        [Fact]
        public async Task TransientFailureRetriesThenCompletesAndSpacesRequests()
        {
            var job = new ReconJob(1, 1, "192.0.2.1", Guid.NewGuid());
            var complete = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var store = new Mock<IReconJobStore>();
            store.Setup(s => s.ClaimAsync(It.IsAny<CancellationToken>())).ReturnsAsync(job);
            store.Setup(s => s.FailAsync(job, It.IsAny<string>(), true, It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            store.Setup(s => s.CompleteAsync(job, It.IsAny<ReconScan>(), It.IsAny<CancellationToken>()))
                .Returns(() => { complete.TrySetResult(true); return Task.CompletedTask; });
            var calls = 0;
            DateTime first = default;
            using var client = ShodanScannerTest.Client((_, _) =>
            {
                if (Interlocked.Increment(ref calls) == 1)
                {
                    first = DateTime.UtcNow;
                    return Task.FromResult(ShodanScannerTest.Response(HttpStatusCode.ServiceUnavailable, "{}"));
                }
                Assert.True(DateTime.UtcNow - first >= TimeSpan.FromMilliseconds(40));
                return Task.FromResult(ShodanScannerTest.Response(HttpStatusCode.OK, ShodanScannerTest.HostJson));
            });
            using var worker = Worker(store.Object, ShodanScannerTest.Scanner(client));
            try
            {
                await worker.StartAsync(CancellationToken.None);
                await complete.Task.WaitAsync(TimeSpan.FromSeconds(3));
            }
            finally { await worker.StopAsync(CancellationToken.None); }
            Assert.Equal(2, calls);
            store.Verify(s => s.FailAsync(job, It.IsAny<string>(), true, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task ShutdownCancelsInFlightLookupAndRequeuesItsLease()
        {
            var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var job = new ReconJob(1, 1, "192.0.2.1", Guid.NewGuid());
            var store = new Mock<IReconJobStore>();
            store.Setup(s => s.ClaimAsync(It.IsAny<CancellationToken>())).ReturnsAsync(job);
            using var client = ShodanScannerTest.Client(async (_, token) =>
            {
                started.TrySetResult(true);
                await Task.Delay(Timeout.Infinite, token);
                return ShodanScannerTest.Response(HttpStatusCode.OK, "{}");
            });
            using var worker = Worker(store.Object, ShodanScannerTest.Scanner(client));
            try
            {
                await worker.StartAsync(CancellationToken.None);
                await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
            }
            finally { await worker.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(3)); }
            store.Verify(s => s.FailAsync(job, It.IsAny<string>(), true, It.IsAny<CancellationToken>()), Times.Once);
            store.Verify(s => s.CompleteAsync(It.IsAny<ReconJob>(), It.IsAny<ReconScan>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }

        private static ShodanWorker Worker(IReconJobStore store, ShodanScanner scanner) =>
            new ShodanWorker(store, scanner, Options.Create(new ShodanOptions
            {
                ApiKey = "test&key",
                RequestIntervalSeconds = .05,
                RetryDelaySeconds = .05,
                MaxRetryDelaySeconds = .1,
                PollIntervalSeconds = .05
            }), NullLogger<ShodanWorker>.Instance);
    }
}
