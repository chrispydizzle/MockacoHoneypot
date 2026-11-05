using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Mockaco.Responses;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;
using Xunit;

namespace Mockaco.Tests.Responses
{
    public class ProfileResponderTest
    {
        private static ProfileResponder Responder() => new ProfileResponder(
            ResponseProfiles.Load(Path.Combine(AppContext.BaseDirectory, "Profiles")),
            Options.Create(new HoneypotOptions()));

        [Theory]
        [InlineData("GET", "/ping", 200)]
        [InlineData("GET", "/ping/", 200)]
        [InlineData("GET", "/a/b", 501)]
        [InlineData("HEAD", "/ping", 501)]
        [InlineData("DELETE", "/ping", 501)]
        public async Task PreservesMethodAndRouteBoundaries(string method, string path, int expectedStatus)
        {
            var context = Context(method, path);
            await Responder().InvokeAsync(context);
            Assert.Equal(expectedStatus, context.Response.StatusCode);
            if (expectedStatus == 200) Assert.Equal(0, context.Response.Body.Length);
        }

        [Fact]
        public async Task PreservesOptionsHeadersWithoutAResponseBody()
        {
            var context = Context("OPTIONS", "/probe");
            await Responder().InvokeAsync(context);
            Assert.Equal(204, context.Response.StatusCode);
            Assert.Equal("*", context.Response.Headers["Access-Control-Allow-Origin"]);
            Assert.Equal("POST, OPTIONS", context.Response.Headers["Access-Control-Allow-Methods"]);
            Assert.Equal("Content-Type", context.Response.Headers["Access-Control-Allow-Headers"]);
            Assert.Equal(0, context.Response.Body.Length);
        }

        [Theory]
        [InlineData("/", 1)]
        [InlineData("/json_rpc", 4)]
        [InlineData("/eh/probe/", 1)]
        public async Task GeneratesActualSampleArraysInTheJsonRpcEnvelope(string path, int groups)
        {
            var context = Context("POST", path);
            context.Request.ContentType = "application/json";
            context.Request.Body = new MemoryStream(System.Text.Encoding.UTF8.GetBytes("{malformed"));
            await Responder().InvokeAsync(context);
            Assert.Equal(200, context.Response.StatusCode);
            Assert.Equal("application/json", context.Response.ContentType);
            context.Response.Body.Position = 0;
            using var body = await JsonDocument.ParseAsync(context.Response.Body);
            Assert.Equal(1, body.RootElement.GetProperty("id").GetInt32());
            Assert.Equal("2.0", body.RootElement.GetProperty("jsonrpc").GetString());
            var result = body.RootElement.GetProperty("result");
            Assert.Equal(groups, result.GetArrayLength());
            var expectedFamilies = path.StartsWith("/eh/")
                ? new[] { NaughtyStrings.TheNaughtyStrings.ScriptInjection }
                : groups == 1 ? new[] { NaughtyStrings.TheNaughtyStrings.SQLInjection }
                : new[] { NaughtyStrings.TheNaughtyStrings.SQLInjection, NaughtyStrings.TheNaughtyStrings.QuotationMarks,
                    NaughtyStrings.TheNaughtyStrings.RightToLeftStrings, NaughtyStrings.TheNaughtyStrings.TrickUnicode };
            for (var index = 0; index < groups; index++)
            {
                Assert.Equal(8, result[index].GetArrayLength());
                Assert.All(result[index].EnumerateArray(), item => Assert.Contains(item.GetString(), expectedFamilies[index]));
            }
            Assert.Equal(0, context.Request.Body.Position);
        }

        [Fact]
        public async Task SupportsLiteralBodiesWithoutInterpretingThemAsCode()
        {
            var profiles = ResponseProfiles.Parse(new[] {
                """{"request":{"method":"GET","route":"/literal"},"response":{"status":201,"body":{"text":"<#= 1 + 1 #>"}}}"""
            });
            var context = Context("GET", "/literal");
            await new ProfileResponder(profiles, Options.Create(new HoneypotOptions())).InvokeAsync(context);
            Assert.Equal(201, context.Response.StatusCode);
            context.Response.Body.Position = 0;
            using var body = await JsonDocument.ParseAsync(context.Response.Body);
            Assert.Equal("<#= 1 + 1 #>", body.RootElement.GetProperty("text").GetString());
        }

        [Theory]
        [InlineData("""{"$generator":"missing","count":8}""")]
        [InlineData("""{"$generator":"SQLInjection","count":0}""")]
        public void RejectsInvalidGeneratorsBeforeServingRequests(string generator)
        {
            var json = """{"request":{"method":"POST","route":"/"},"response":{"body":""" + generator + "}}";
            Assert.Throws<InvalidDataException>(() => ResponseProfiles.Parse(new[] { json }));
        }

        [Fact]
        public async Task WritesLiteralTextForAliasesAndSuppressesOnlyTheHeadBody()
        {
            var profiles = ResponseProfiles.Parse(new[] {
                """{"request":{"methods":["GET","HEAD"],"routes":["/config","/app/config"]},"response":{"bodyFormat":"text","body":"NAME=café\nSCRIPT=<#= 1 + 1 #>\n"}}"""
            });
            var responder = new ProfileResponder(profiles, Options.Create(new HoneypotOptions()));
            foreach (var path in new[] { "/config", "/app/config" })
            {
                var get = Context("GET", path);
                await responder.InvokeAsync(get);
                Assert.Equal("NAME=café\nSCRIPT=<#= 1 + 1 #>\n", Text(get));
                Assert.Equal("text/plain; charset=utf-8", get.Response.ContentType);
                Assert.Equal(get.Response.Body.Length, get.Response.ContentLength);
                var head = Context("HEAD", path);
                await responder.InvokeAsync(head);
                Assert.Equal(get.Response.StatusCode, head.Response.StatusCode);
                Assert.Equal(get.Response.ContentType, head.Response.ContentType);
                Assert.Equal(get.Response.ContentLength, head.Response.ContentLength);
                Assert.Equal(0, head.Response.Body.Length);
            }
            Assert.Null(profiles.Match(Context("POST", "/config").Request));
            Assert.Null(profiles.Match(Context("GET", "/config/extra").Request));
        }

        [Fact]
        public async Task KeepsJsonStringsQuotedUnlessTextFormatIsSelected()
        {
            var profiles = ResponseProfiles.Parse(new[] {
                """{"request":{"method":"GET","route":"/string"},"response":{"body":"line\nvalue"}}"""
            });
            var context = Context("GET", "/string");
            await new ProfileResponder(profiles, Options.Create(new HoneypotOptions())).InvokeAsync(context);
            Assert.Equal("\"line\\nvalue\"", Text(context));
            Assert.Equal("application/json", context.Response.ContentType);
        }

        [Theory]
        [InlineData("""{"bodyFormat":"text","body":{"key":1}}""")]
        [InlineData("""{"bodyFormat":"base64","body":"not base64!"}""")]
        [InlineData("""{"bodyFormat":"script","body":"1+1"}""")]
        public void RejectsInvalidLiteralFormatsAtStartup(string response)
        {
            var json = """{"request":{"method":"GET","route":"/"},"response":""" + response + "}";
            Assert.Throws<InvalidDataException>(() => ResponseProfiles.Parse(new[] { json }));
        }

        [Theory]
        [InlineData("""{"method":"GET","methods":["HEAD"],"route":"/"}""")]
        [InlineData("""{"method":"GET","route":"/","routes":["/two"]}""")]
        [InlineData("""{"methods":[],"route":"/"}""")]
        [InlineData("""{"method":"GET","routes":[""]}""")]
        public void RejectsAmbiguousOrEmptyAliasesAtStartup(string request)
        {
            var json = """{"request":""" + request + ""","response":{}}""";
            Assert.Throws<InvalidDataException>(() => ResponseProfiles.Parse(new[] { json }));
        }

        public static IEnumerable<object[]> ObservedRequests()
        {
            using var document = JsonDocument.Parse(File.ReadAllText(
                Path.Combine(AppContext.BaseDirectory, "Responses", "DecoyRequests.json")));
            foreach (var group in document.RootElement.EnumerateArray())
                foreach (var path in group.GetProperty("paths").EnumerateArray())
                {
                    var method = group.TryGetProperty("method", out var value) ? value.GetString() : "GET";
                    yield return new object[] { method, path.GetString(), group.GetRawText() };
                    if (method == "GET") yield return new object[] { "HEAD", path.GetString(), group.GetRawText() };
                }
        }

        [Theory]
        [MemberData(nameof(ObservedRequests))]
        public async Task ServesObservedShapesWithNativeRepresentations(string method, string path, string expectation)
        {
            using var document = JsonDocument.Parse(expectation);
            var expected = document.RootElement;
            var context = Context(method, path);
            context.Request.QueryString = new QueryString("?probe=untrusted");
            await Responder().InvokeAsync(context);
            Assert.Equal(expected.GetProperty("status").GetInt32(), context.Response.StatusCode);
            Assert.Equal(expected.GetProperty("contentType").GetString(), context.Response.ContentType);
            if (expected.TryGetProperty("headers", out var headers))
                foreach (var header in headers.EnumerateObject())
                    Assert.Equal(header.Value.GetString(), context.Response.Headers[header.Name].ToString());
            if (method == "HEAD")
            {
                Assert.Equal(0, context.Response.Body.Length);
                Assert.True(context.Response.ContentLength > 0);
                return;
            }
            Assert.Equal(context.Response.Body.Length, context.Response.ContentLength);
            if (expected.TryGetProperty("binary", out _))
            {
                var bytes = ((MemoryStream)context.Response.Body).ToArray();
                Assert.Equal(new byte[] { 0, 0, 1, 0, 1, 0 }, bytes.Take(6));
                Assert.True(bytes.Length > 22);
                Assert.Equal(bytes.Length, (long)BitConverter.ToUInt32(bytes, 14) + BitConverter.ToUInt32(bytes, 18));
                return;
            }
            var text = Text(context);
            foreach (var marker in expected.GetProperty("contains").EnumerateArray())
                Assert.Contains(marker.GetString(), text);
            var contentType = context.Response.ContentType;
            if (contentType.Contains("json")) using (JsonDocument.Parse(text)) { }
            if (contentType.Contains("xml")) XDocument.Parse(text);
            if (contentType.StartsWith("text/")) Assert.DoesNotContain("\\n", text);
        }

        [Fact]
        public async Task KeepsDecoyConfigurationValuesConsistentAcrossFormats()
        {
            async Task<string> Get(string path)
            {
                var context = Context("GET", path);
                await Responder().InvokeAsync(context);
                return Text(context);
            }
            var env = (await Get("/.env")).Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Where(line => !line.StartsWith('#')).Select(line => line.Split('=', 2))
                .ToDictionary(parts => parts[0], parts => parts[1].Trim('"'));
            using var json = JsonDocument.Parse(await Get("/config.json"));
            Assert.Equal(env["DB_HOST"], json.RootElement.GetProperty("database").GetProperty("host").GetString());
            Assert.Equal(env["DB_DATABASE"], json.RootElement.GetProperty("database").GetProperty("name").GetString());
            Assert.Equal(env["DB_PASSWORD"], json.RootElement.GetProperty("database").GetProperty("password").GetString());
            var credentials = await Get("/.aws/credentials");
            Assert.Contains("aws_access_key_id = " + env["AWS_ACCESS_KEY_ID"], credentials);
            Assert.Contains("aws_secret_access_key = " + env["AWS_SECRET_ACCESS_KEY"], credentials);
            Assert.Matches("^AKIA[A-Z2-7]{16}$", env["AWS_ACCESS_KEY_ID"]);
            Assert.Equal(40, env["AWS_SECRET_ACCESS_KEY"].Length);
            Assert.Equal(32, Convert.FromBase64String(env["APP_KEY"].Substring("base64:".Length)).Length);
            Assert.Equal(await Get("/.git/config"), await Get("/assets../.git/config"));
            Assert.Contains("MYSQL_DATABASE: " + env["DB_DATABASE"], await Get("/docker-compose.prod.yml"));
        }

        private static string Text(DefaultHttpContext context) =>
            Encoding.UTF8.GetString(((MemoryStream)context.Response.Body).ToArray());

        private static DefaultHttpContext Context(string method, string path)
        {
            var context = new DefaultHttpContext();
            context.Request.Method = method;
            context.Request.Path = path;
            context.Response.Body = new MemoryStream();
            return context;
        }
    }
}
