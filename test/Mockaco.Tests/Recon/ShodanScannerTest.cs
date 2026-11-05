using Microsoft.Extensions.Options;
using Mockaco.Recon;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Mockaco.Tests.Recon
{
    public class ShodanScannerTest
    {
        internal const string HostJson = """
            {"ip_str":"192.0.2.1","hostnames":["example.test","example.test"],"org":"Example",
             "last_update":"2025-01-02T03:04:05.123456","vulns":["CVE-2000-0001"],
             "data":[
               {"port":443,"transport":"tcp","_shodan":{"module":"https"},"product":"nginx",
                "version":"1.24","data":"HTTP/1.1 200 OK\r\nServer: nginx","timestamp":"2025-01-02T03:04:05.123456"},
               {"port":53,"transport":"udp","_shodan":{"module":"dns-udp"},"data":"DNS banner","timestamp":"2024-12-01T00:00:00"}
             ]}
            """;

        [Fact]
        public async Task LooksUpFullHostRecordsAndPreservesEvidenceAndObservationDates()
        {
            using var client = Client((request, _) =>
            {
                Assert.Equal(HttpMethod.Get, request.Method);
                Assert.Equal("https://api.shodan.io/shodan/host/192.0.2.1?key=test%26key&history=false&minify=false",
                    request.RequestUri.AbsoluteUri);
                return Task.FromResult(Response(HttpStatusCode.OK, HostJson));
            });
            var before = DateTime.UtcNow;
            var scan = await Scanner(client).ScanAsync("::ffff:192.0.2.1", CancellationToken.None);
            Assert.Equal(new[] { "example.test" }, scan.Hostnames);
            Assert.Equal(2, scan.Ports.Count);
            Assert.Equal("https nginx 1.24\nHTTP/1.1 200 OK\r\nServer: nginx", scan.Ports[0].Detail);
            Assert.Equal(new DateTime(2025, 1, 2, 3, 4, 5, DateTimeKind.Utc).AddTicks(1234560),
                scan.Ports[0].ObservedAtUtc);
            Assert.Equal("udp", scan.Ports[1].Protocol);
            Assert.StartsWith("dns\n", scan.Ports[1].Detail);
            Assert.Equal(HostJson, scan.Evidence.ResponseJson);
            Assert.Equal(200, scan.Evidence.StatusCode);
            Assert.InRange(scan.Evidence.RetrievedAtUtc, before, DateTime.UtcNow);
        }

        [Fact]
        public async Task NoInformationIsACompletedEmptyLookupWithEvidence()
        {
            const string body = """{"error":"No information available for that IP."}""";
            using var client = Client((_, _) => Task.FromResult(Response(HttpStatusCode.NotFound, body)));
            var scan = await Scanner(client).ScanAsync("192.0.2.1", CancellationToken.None);
            Assert.Empty(scan.Ports);
            Assert.Empty(scan.Hostnames);
            Assert.Equal(404, scan.Evidence.StatusCode);
            Assert.Equal(body, scan.Evidence.ResponseJson);
        }

        [Theory]
        [InlineData(401, true, true)]
        [InlineData(403, true, true)]
        [InlineData(429, true, false)]
        [InlineData(500, true, false)]
        [InlineData(503, true, false)]
        [InlineData(400, false, false)]
        [InlineData(302, false, false)]
        public async Task ClassifiesApiFailuresWithoutExposingKeyOrResponse(int status, bool retry, bool pause)
        {
            using var client = Client((_, _) => Task.FromResult(Response((HttpStatusCode)status, "test&key")));
            var error = await Assert.ThrowsAsync<ShodanLookupException>(() =>
                Scanner(client).ScanAsync("192.0.2.1", CancellationToken.None));
            Assert.Equal(retry, error.Retryable);
            Assert.Equal(pause, error.Pause);
            Assert.DoesNotContain("test&key", error.ToString());
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task HonorsRetryAfterSecondsAndDates(bool useDate)
        {
            var retryAt = DateTimeOffset.UtcNow.AddMinutes(2);
            using var client = Client((_, _) =>
            {
                var response = Response(HttpStatusCode.TooManyRequests, "{}");
                response.Headers.RetryAfter = useDate ? new RetryConditionHeaderValue(retryAt)
                    : new RetryConditionHeaderValue(TimeSpan.FromSeconds(120));
                return Task.FromResult(response);
            });
            var error = await Assert.ThrowsAsync<ShodanLookupException>(() =>
                Scanner(client).ScanAsync("192.0.2.1", CancellationToken.None));
            Assert.InRange(error.RetryAfter.Value.TotalSeconds, 118, 120);
        }

        [Theory]
        [InlineData(200, "not json")]
        [InlineData(200, "{}")]
        [InlineData(200, "{\"ip_str\":\"192.0.2.2\",\"data\":[]}")]
        [InlineData(200, "{\"ip_str\":\"192.0.2.1\",\"data\":[{\"port\":0,\"transport\":\"tcp\"}]}")]
        [InlineData(404, "{\"error\":\"Wrong endpoint\"}")]
        public async Task DoesNotSilentlyCompleteMalformedOrMismatchedResponses(int status, string body)
        {
            using var client = Client((_, _) => Task.FromResult(Response((HttpStatusCode)status, body)));
            await Assert.ThrowsAsync<ShodanLookupException>(() =>
                Scanner(client).ScanAsync("192.0.2.1", CancellationToken.None));
        }

        [Fact]
        public async Task NetworkErrorsAreRetryableAndCancellationPropagates()
        {
            using var failed = Client((_, _) => throw new HttpRequestException("URI contains test&key"));
            var error = await Assert.ThrowsAsync<ShodanLookupException>(() =>
                Scanner(failed).ScanAsync("192.0.2.1", CancellationToken.None));
            Assert.True(error.Retryable);
            Assert.DoesNotContain("test&key", error.ToString());
            using var cancelled = Client(async (_, token) =>
            {
                await Task.Delay(Timeout.Infinite, token);
                return Response(HttpStatusCode.OK, HostJson);
            });
            using var stop = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                Scanner(cancelled).ScanAsync("192.0.2.1", stop.Token));
        }

        internal static ShodanScanner Scanner(HttpClient client) =>
            new ShodanScanner(client, Options.Create(new ShodanOptions { ApiKey = "test&key" }));
        internal static HttpClient Client(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) =>
            new HttpClient(new Handler(send));
        internal static HttpResponseMessage Response(HttpStatusCode status, string body) =>
            new HttpResponseMessage(status) { Content = new StringContent(body) };
        private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send)
            : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) =>
                send(request, token);
        }
    }
}
