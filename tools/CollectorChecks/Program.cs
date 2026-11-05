using System.Collections.Concurrent;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Dapper;
using Microsoft.Extensions.Configuration;
using Mockaco.Analytics;

string Value(string flag, string fallback)
{
    var index = Array.IndexOf(args, flag);
    return index < 0 ? fallback : args[index + 1];
}
var root = new DirectoryInfo(AppContext.BaseDirectory);
while (root != null && !Directory.Exists(Path.Combine(root.FullName, "HttpLog"))) root = root.Parent;
if (root == null) throw new DirectoryNotFoundException("Run this tool from a build inside the repository.");
var application = Path.GetFullPath(Value("--app", Path.Combine(root.FullName, "artifacts", "collector-publish", "Mockaco.dll")));
if (!File.Exists(application)) throw new FileNotFoundException("Publish the collector first or supply --app.", application);
var masterConnection = Value("--sql", "Data Source=localhost;Initial Catalog=master;Integrated Security=True;Encrypt=False;");
var database = "MockacoCollectorChecks_" + Guid.NewGuid().ToString("N");
var connectionString = new SqlConnectionStringBuilder(masterConnection) { InitialCatalog = database }.ConnectionString;
var created = false;
var started = false;
using var process = new Process();
var output = new ConcurrentQueue<string>();
var listening = new TaskCompletionSource<Uri>(TaskCreationOptions.RunContinuationsAsynchronously);
try
{
    using (var master = new SqlConnection(masterConnection))
    {
        await master.ExecuteAsync($"CREATE DATABASE [{database}]");
        created = true;
    }
    using (var connection = new SqlConnection(connectionString))
        foreach (var file in new[] { "Host.sql", "Job.sql", "HostJob.sql", "Request.sql", "Header.sql", "Discovery.sql", "dbo.Hostname.sql", "ReconEvidence.sql" })
            await connection.ExecuteAsync(await File.ReadAllTextAsync(Path.Combine(root.FullName, "HttpLog", file)));

    process.StartInfo = new ProcessStartInfo("dotnet")
    {
        WorkingDirectory = Path.GetDirectoryName(application),
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true
    };
    foreach (var argument in new[] { application, "--urls", "http://127.0.0.1:0",
        "--ConnectionStrings:HttpDb", connectionString })
        process.StartInfo.ArgumentList.Add(argument);
    process.StartInfo.Environment["ASPNETCORE_ENVIRONMENT"] = "Production";
    process.StartInfo.Environment["Shodan__ApiKey"] = "";
    process.OutputDataReceived += Observe;
    process.ErrorDataReceived += Observe;
    process.EnableRaisingEvents = true;
    process.Exited += (_, _) => listening.TrySetException(new InvalidOperationException("Collector exited before becoming ready."));
    started = process.Start();
    process.BeginOutputReadLine();
    process.BeginErrorReadLine();
    var address = await listening.Task.WaitAsync(TimeSpan.FromSeconds(30));
    using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
    { BaseAddress = address, Timeout = TimeSpan.FromSeconds(30) };

    await Task.WhenAll(Enumerable.Range(0, 24).Select(async index =>
    {
        using var response = await client.GetAsync($"/Probe?value={index}%26x");
        Require(response.StatusCode == HttpStatusCode.OK, "Concurrent capture failed.");
        Require((await response.Content.ReadAsByteArrayAsync()).Length == 0, "GET profile gained a body.");
    }));
    foreach (var path in new[] { "/", "/json_rpc", "/eh/probe/" })
    {
        using var response = await client.PostAsync(path, new StringContent("{not-json", Encoding.UTF8, "application/json"));
        Require(response.StatusCode == HttpStatusCode.OK, $"POST profile failed: {path}");
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var result = body.RootElement.GetProperty("result");
        Require(result.GetArrayLength() == (path == "/json_rpc" ? 4 : 1), "Incorrect generator groups.");
        Require(result[0].GetArrayLength() == 8, "Generated samples were not serialized as arrays.");
    }
    using (var request = new HttpRequestMessage(HttpMethod.Options, "/probe"))
    using (var response = await client.SendAsync(request))
    {
        Require(response.StatusCode == HttpStatusCode.NoContent, "OPTIONS status changed.");
        Require(response.Headers.GetValues("Access-Control-Allow-Origin").Single() == "*", "OPTIONS headers changed.");
    }
    foreach (var path in new[] { "/not/a/profile", "/_mockaco/verification" })
    {
        using var response = await client.GetAsync(path);
        Require(response.StatusCode == HttpStatusCode.NotImplemented, "Unmatched path or retired verification route was not handled normally.");
    }

    var decoyRequests = new List<(string Method, string Path)>();
    var responseDirectory = Path.Combine(root.FullName, "artifacts", "collector-responses");
    Directory.CreateDirectory(responseDirectory);
    var savedResponses = new Dictionary<string, string>
    {
        ["/.env"] = ".env",
        ["/docker-compose.prod.yml"] = "compose.yml",
        ["/.git/config"] = "git.config",
        ["/favicon.ico"] = "favicon.ico"
    };
    using (var fixture = JsonDocument.Parse(await File.ReadAllTextAsync(
        Path.Combine(root.FullName, "test", "Mockaco.Tests", "Responses", "DecoyRequests.json"))))
        foreach (var group in fixture.RootElement.EnumerateArray())
            foreach (var pathElement in group.GetProperty("paths").EnumerateArray())
            {
                var path = pathElement.GetString();
                var method = group.TryGetProperty("method", out var value) ? value.GetString() : "GET";
                long? getLength = null;
                foreach (var verb in method == "GET" ? new[] { "GET", "HEAD" } : new[] { method })
                {
                    using var request = new HttpRequestMessage(new HttpMethod(verb), path + "?probe=fixture%26x");
                    if (verb == "POST")
                        request.Content = new StringContent("username=probe&password=invalid", Encoding.UTF8, "application/x-www-form-urlencoded");
                    using var response = await client.SendAsync(request);
                    var label = $"{verb} {path}";
                    Require((int)response.StatusCode == group.GetProperty("status").GetInt32(), $"Incorrect status: {label}");
                    Require(response.Content.Headers.ContentType?.ToString() == group.GetProperty("contentType").GetString(),
                        $"Incorrect content type: {label}");
                    Require(response.Headers.Server.ToString() == "nginx/1.24.0", $"Incorrect server identity: {label}");
                    if (group.TryGetProperty("headers", out var headers))
                        foreach (var header in headers.EnumerateObject())
                        {
                            var found = response.Headers.TryGetValues(header.Name, out var values)
                                || response.Content.Headers.TryGetValues(header.Name, out values);
                            Require(found && values.Single() == header.Value.GetString(), $"Incorrect {header.Name}: {label}");
                        }
                    var bytes = await response.Content.ReadAsByteArrayAsync();
                    if (verb == "HEAD")
                    {
                        Require(bytes.Length == 0 && response.Content.Headers.ContentLength == getLength, $"HEAD differed from GET: {label}");
                    }
                    else
                    {
                        getLength = bytes.Length;
                        Require(response.Content.Headers.ContentLength == bytes.Length && bytes.Length > 0, $"Incorrect body length: {label}");
                        if (group.TryGetProperty("binary", out _))
                            Require(bytes.Take(6).SequenceEqual(new byte[] { 0, 0, 1, 0, 1, 0 })
                                && BitConverter.ToUInt32(bytes, 14) + BitConverter.ToUInt32(bytes, 18) == bytes.Length,
                                $"Invalid icon representation: {label}");
                        else
                        {
                            var text = Encoding.UTF8.GetString(bytes);
                            foreach (var marker in group.GetProperty("contains").EnumerateArray())
                                Require(text.Contains(marker.GetString(), StringComparison.Ordinal), $"Missing body marker: {label}");
                            var contentType = response.Content.Headers.ContentType.MediaType;
                            if (contentType.Contains("json")) using (JsonDocument.Parse(text)) { }
                            if (contentType.Contains("xml")) XDocument.Parse(text);
                        }
                        if (savedResponses.TryGetValue(path, out var filename))
                            await File.WriteAllBytesAsync(Path.Combine(responseDirectory, filename), bytes);
                    }
                    decoyRequests.Add((verb, path));
                }
            }

    var expectedRequests = 30 + decoyRequests.Count;
    using (var connection = new SqlConnection(connectionString))
    {
        Require(await connection.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM dbo.Host") == 1, "Concurrent first requests duplicated hosts.");
        Require(await connection.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM dbo.Request") == expectedRequests, "Request capture lost records.");
        Require(await connection.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM dbo.Request WHERE CONVERT(nvarchar(max), Target) COLLATE Latin1_General_100_BIN2 = '/Probe' AND QueryString LIKE '%26x'") == 24,
            "Capture changed path case or query encoding.");
        Require(await connection.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM dbo.HostJob") == 0,
            "The no-job fixture unexpectedly scheduled a scan.");
        var captured = (await connection.QueryAsync<(string Method, string Path)>(
            "SELECT Method, CONVERT(nvarchar(max), Target) AS Path FROM dbo.Request")).ToHashSet();
        Require(decoyRequests.All(captured.Contains), "Decoy requests were not captured with their original method and path.");
    }
    using (var store = new AnalyticsStore(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string>
    {
        ["ConnectionStrings:HttpDb"] = connectionString
    }).Build()))
    {
        var analysis = await store.GetAsync(AnalysisWindow.Parse(null, null), false, CancellationToken.None);
        Require(analysis.Snapshot.Sources.Count == 1 && analysis.Snapshot.Sources[0].Requests == expectedRequests,
            "The atlas could not consume the new collector's records.");
    }
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        result = "profiles-and-capture-passed",
        requests = expectedRequests,
        decoyRequests = decoyRequests.Count,
        responseDirectory,
        checks = new[] { "published startup", "original profiles", "decoy wire representations", "HEAD parity",
            "concurrent SQL capture", "raw path/query", "retired verification route", "atlas compatibility" }
    }));
    using (var connection = new SqlConnection(connectionString))
        await connection.ExecuteAsync("DROP TABLE dbo.Header; DROP TABLE dbo.Request;");
    using (var response = await client.GetAsync("/capture-unavailable"))
        Require(response.StatusCode == HttpStatusCode.ServiceUnavailable, "A failed SQL capture returned success.");
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        result = "passed",
        requests = expectedRequests,
        decoyRequests = decoyRequests.Count,
        responseDirectory,
        checks = new[] { "published startup", "original profiles", "decoy wire representations", "HEAD parity", "concurrent SQL capture", "raw path/query",
            "retired verification route", "atlas compatibility", "capture failure status" }
    }));
}
catch
{
    foreach (var line in output.TakeLast(12)) Console.Error.WriteLine(line);
    throw;
}
finally
{
    if (started && !process.HasExited)
    {
        process.Kill(entireProcessTree: true);
        await process.WaitForExitAsync();
    }
    SqlConnection.ClearAllPools();
    if (created)
    {
        using var master = new SqlConnection(masterConnection);
        await master.ExecuteAsync($"ALTER DATABASE [{database}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{database}];");
        Console.WriteLine($"Removed owned database {database}.");
    }
}

void Observe(object sender, DataReceivedEventArgs eventArgs)
{
    if (eventArgs.Data == null) return;
    output.Enqueue(eventArgs.Data);
    var match = Regex.Match(eventArgs.Data, @"Now listening on: (http://127\.0\.0\.1:\d+)");
    if (match.Success) listening.TrySetResult(new Uri(match.Groups[1].Value));
}

void Require(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}
