using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Mockaco.Capture;
using Mockaco.Middlewares;
using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Mockaco.Tests.Middlewares
{
    public class DatabaseLoggingMiddlewareTest
    {
        [Fact]
        public async Task CapturesTheOriginalRequestBeforeGeneratingAResponse()
        {
            var log = new RecordingLog();
            var context = new DefaultHttpContext();
            context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.10");
            context.Request.Method = "POST";
            context.Request.Host = new HostString("example.test", 8080);
            context.Request.Path = "/Case/Path";
            context.Request.QueryString = new QueryString("?token=a%26b");
            var responded = false;
            var middleware = new DatabaseLoggingMiddleware(_ =>
            {
                Assert.NotNull(log.Request);
                responded = true;
                return Task.CompletedTask;
            }, log, NullLogger<DatabaseLoggingMiddleware>.Instance);

            await middleware.InvokeAsync(context);

            Assert.True(responded);
            Assert.Equal(new CapturedRequest("192.0.2.10", "example.test:8080", "/Case/Path", "POST", "?token=a%26b"), log.Request);
        }

        [Fact]
        public async Task AFailedCaptureDoesNotPretendTheRequestWasRecorded()
        {
            var context = new DefaultHttpContext();
            context.Response.Body = new MemoryStream();
            var responded = false;
            var middleware = new DatabaseLoggingMiddleware(_ =>
            {
                responded = true;
                return Task.CompletedTask;
            }, new RecordingLog { Failure = new IOException("Database unavailable") },
                NullLogger<DatabaseLoggingMiddleware>.Instance);

            await middleware.InvokeAsync(context);

            Assert.False(responded);
            Assert.Equal(503, context.Response.StatusCode);
        }

        private sealed class RecordingLog : IRequestLog
        {
            public CapturedRequest Request { get; private set; }
            public Exception Failure { get; init; }
            public Task WriteAsync(CapturedRequest request, CancellationToken cancellationToken)
            {
                if (Failure != null) throw Failure;
                Request = request;
                return Task.CompletedTask;
            }
        }
    }
}
