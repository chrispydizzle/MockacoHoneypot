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
            Assert.Equal("192.0.2.10", log.Request.SourceAddress);
            Assert.Equal("example.test:8080", log.Request.TargetHost);
            Assert.Equal("/Case/Path", log.Request.Target);
            Assert.Equal("POST", log.Request.Method);
            Assert.Equal("?token=a%26b", log.Request.QueryString);
            Assert.NotNull(log.Request.Body);
            Assert.Empty(log.Request.Body);
            Assert.Null(log.Request.ContentType);
        }

        [Theory]
        [InlineData(true, "POST", "application/octet-stream")]
        [InlineData(false, "GET", null)]
        public async Task CapturesExactBodyBytesAndLeavesThemReadable(bool seekable, string method, string contentType)
        {
            var bytes = new byte[65537];
            for (var index = 0; index < bytes.Length; index++) bytes[index] = (byte)index;
            using var input = seekable ? new MemoryStream(bytes) : new NonSeekableStream(bytes);
            var context = new DefaultHttpContext();
            context.Request.Method = method;
            context.Request.ContentType = contentType;
            context.Request.Body = input;
            var log = new RecordingLog();
            var responded = false;
            var middleware = new DatabaseLoggingMiddleware(async nextContext =>
            {
                Assert.Equal(bytes, log.Request.Body);
                Assert.Equal(contentType, log.Request.ContentType);
                using var downstream = new MemoryStream();
                await nextContext.Request.Body.CopyToAsync(downstream);
                Assert.Equal(bytes, downstream.ToArray());
                responded = true;
            }, log, NullLogger<DatabaseLoggingMiddleware>.Instance);

            try
            {
                await middleware.InvokeAsync(context);
                Assert.True(responded);
                Assert.True(context.Request.Body.CanRead);
            }
            finally
            {
                await context.Request.Body.DisposeAsync();
            }
        }

        [Fact]
        public async Task AnIncompleteBodyIsNotRecordedOrHandledAsACompleteRequest()
        {
            using var input = new NonSeekableStream(new byte[] { 1, 2, 3 }) { FailRead = true };
            var context = new DefaultHttpContext();
            context.Request.Body = input;
            var log = new RecordingLog();
            var responded = false;
            var middleware = new DatabaseLoggingMiddleware(_ =>
            {
                responded = true;
                return Task.CompletedTask;
            }, log, NullLogger<DatabaseLoggingMiddleware>.Instance);

            try
            {
                await Assert.ThrowsAsync<IOException>(() => middleware.InvokeAsync(context));
                Assert.Null(log.Request);
                Assert.False(responded);
            }
            finally
            {
                await context.Request.Body.DisposeAsync();
            }
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

        private sealed class NonSeekableStream : MemoryStream
        {
            public NonSeekableStream(byte[] bytes) : base(bytes) { }
            public bool FailRead { get; init; }
            public override bool CanSeek => false;
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (FailRead) throw new IOException("Incomplete request body");
                return base.ReadAsync(buffer, cancellationToken);
            }
        }
    }
}
