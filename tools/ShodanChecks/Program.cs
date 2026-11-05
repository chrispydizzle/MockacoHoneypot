using System.Data.SqlClient;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Dapper;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Mockaco.Analytics;
using Mockaco.Recon;

var root = new DirectoryInfo(AppContext.BaseDirectory);
while (root != null && !Directory.Exists(Path.Combine(root.FullName, "HttpLog"))) root = root.Parent;
if (root == null) throw new DirectoryNotFoundException("Build this tool inside the repository.");
var sqlIndex = Array.IndexOf(args, "--sql");
var masterConnection = sqlIndex < 0
    ? "Data Source=localhost;Initial Catalog=master;Integrated Security=True;Encrypt=False;" : args[sqlIndex + 1];
var database = "MockacoShodanChecks_" + Guid.NewGuid().ToString("N");
var connectionString = new SqlConnectionStringBuilder(masterConnection) { InitialCatalog = database }.ConnectionString;
var settings = Options.Create(new ReconOptions { ConnectionString = connectionString });
var nmap = new SqlReconJobStore(settings);
var shodan = new SqlReconJobStore(settings, "Shodan");
var created = false;
var token = CancellationToken.None;
try
{
    using (var master = new SqlConnection(masterConnection))
    {
        await master.ExecuteAsync($"CREATE DATABASE [{database}]");
        created = true;
    }
    using var sql = new SqlConnection(connectionString);
    await sql.OpenAsync();
    foreach (var file in new[] { "Host.sql", "Job.sql", "HostJob.sql", "Request.sql", "Header.sql",
        "Discovery.sql", "dbo.Hostname.sql", "ReconEvidence.sql" })
        await sql.ExecuteAsync(await File.ReadAllTextAsync(Path.Combine(root.FullName, "HttpLog", file)));
    await sql.ExecuteAsync("""
        DROP TABLE dbo.ReconEvidence;
        ALTER TABLE dbo.Job DROP CONSTRAINT DF_Job_Provider;
        ALTER TABLE dbo.Job DROP COLUMN Provider;
        ALTER TABLE dbo.Discovery DROP COLUMN ObservedAtUtc;
        INSERT dbo.Job (Name) VALUES ('LegacyNmap');
        INSERT dbo.Host (IpAddress) VALUES ('192.0.2.1'), ('192.0.2.2'), ('2001:db8::1');
        INSERT dbo.HostJob (HostId, JobId, State)
        SELECT MIN(HostId), MIN(JobId), 0 FROM dbo.Host CROSS JOIN dbo.Job;
        """);
    var migration = await File.ReadAllTextAsync(Path.Combine(root.FullName, "HttpLog", "Migrations", "002-ShodanLookup.sql"));
    await sql.ExecuteAsync(migration);
    await sql.ExecuteAsync(migration);
    Require(await sql.ExecuteScalarAsync<string>("SELECT Provider FROM dbo.Job") == "Nmap", "Legacy job provider not backfilled.");
    Require(await sql.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM dbo.HostJob") == 1, "Migration changed legacy work.");

    var shodanClaims = (await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => shodan.ClaimAsync(token))))
        .Where(job => job != null).ToArray();
    var nmapClaims = (await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => nmap.ClaimAsync(token))))
        .Where(job => job != null).ToArray();
    Require(shodanClaims.Length == 3 && nmapClaims.Length == 3, "Provider queues did not cover all hosts once.");
    Require(shodanClaims.Concat(nmapClaims).Select(job => job.HostJobId).Distinct().Count() == 6, "Duplicate claims.");
    foreach (var (provider, claims) in new[] { ("Shodan", shodanClaims), ("Nmap", nmapClaims) })
        foreach (var job in claims)
            Require(await sql.ExecuteScalarAsync<string>("""
                SELECT Provider FROM dbo.Job j JOIN dbo.HostJob hj ON hj.JobId=j.JobId WHERE hj.HostJobId=@HostJobId
                """, job) == provider, "Claim crossed providers.");
    Require(await sql.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM dbo.Job WHERE Provider='Shodan'") == 1,
        "Concurrent claims duplicated the Shodan job definition.");

    var old = shodanClaims[0];
    await sql.ExecuteAsync("UPDATE dbo.HostJob SET LeaseUntil=DATEADD(second,-1,SYSUTCDATETIME()) WHERE HostJobId=@HostJobId", old);
    Require(await nmap.ClaimAsync(token) == null, "Nmap stole an expired Shodan lease.");
    var reclaimed = await shodan.ClaimAsync(token);
    Require(reclaimed.HostJobId == old.HostJobId && reclaimed.LeaseToken != old.LeaseToken, "Expired lease was not reclaimed.");
    var empty = new ReconScan(Array.Empty<string>(), Array.Empty<ReconPort>());
    try
    {
        await shodan.CompleteAsync(old, empty, token);
        throw new Exception("Stale lease committed.");
    }
    catch (InvalidOperationException exception) when (exception.Message.Contains("lease was lost")) { }
    await shodan.FailAsync(old, "stale", true, token);
    Require(await sql.ExecuteScalarAsync<Guid>("SELECT LeaseToken FROM dbo.HostJob WHERE HostJobId=@HostJobId", old)
        == reclaimed.LeaseToken, "Stale failure overwrote current owner.");
    await shodan.FailAsync(reclaimed, "retry", true, token);
    Require(await nmap.ClaimAsync(token) == null, "Nmap stole a pending Shodan lookup.");
    reclaimed = await shodan.ClaimAsync(token);
    shodanClaims[0] = reclaimed;

    using var client = new HttpClient(new FixtureHandler());
    using var scanner = new ShodanScanner(client, Options.Create(new ShodanOptions { ApiKey = "fixture-only" }));
    var good = await scanner.ScanAsync(reclaimed.Target, token);
    try
    {
        await shodan.CompleteAsync(reclaimed, good with { Hostnames = new[] { "rollback.test", new string('x', 501) } }, token);
        throw new Exception("Expected hostname truncation did not occur.");
    }
    catch (SqlException)
    {
        Require(await sql.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM dbo.ReconEvidence") == 0, "Evidence survived rollback.");
        Require(await sql.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM dbo.Hostname") == 0, "Hostname survived rollback.");
    }
    foreach (var job in nmapClaims)
        await nmap.CompleteAsync(job, new ReconScan(Array.Empty<string>(), new[] { new ReconPort(22, "tcp", "ssh OpenSSH") }), token);
    foreach (var job in shodanClaims)
    {
        var scan = await scanner.ScanAsync(job.Target, token);
        await shodan.CompleteAsync(job, scan, token);
        var raw = await sql.ExecuteScalarAsync<string>("SELECT ResponseJson FROM dbo.ReconEvidence WHERE HostJobId=@HostJobId", job);
        Require(raw == scan.Evidence.ResponseJson, "Raw JSON was altered or truncated.");
        Require(await sql.ExecuteScalarAsync<int>("SELECT State FROM dbo.HostJob WHERE HostJobId=@HostJobId", job) == 1,
            "Lookup did not complete.");
    }
    Require(await nmap.ClaimAsync(token) == null && await shodan.ClaimAsync(token) == null, "Completed jobs were repeated.");
    await sql.ExecuteAsync(migration);

    using var analytics = new AnalyticsStore(new ConfigurationBuilder().AddInMemoryCollection(
        new Dictionary<string, string> { ["ConnectionStrings:HttpDb"] = connectionString }).Build());
    foreach (var job in shodanClaims)
    {
        var detail = await analytics.SourceAsync(job.HostId, new AnalysisWindow(null, null), null, token);
        Require(detail.Jobs.Count == 2 && detail.Jobs.Select(j => j.Provider).Distinct().Count() == 2,
            "Atlas omitted provider provenance.");
        var state = detail.Jobs.Single(j => j.Provider == "Shodan");
        Require(state.RetrievedAtUtc.HasValue && state.RetrievedAtUtc.Value.Offset == TimeSpan.Zero,
            "Retrieval timestamp did not survive as UTC.");
        if (job.Target == "192.0.2.2")
        {
            Require(state.StatusCode == 404 && detail.Services.All(s => s.Provider != "Shodan"),
                "No-data lookup fabricated services or lost its status.");
        }
        else
        {
            var service = detail.Services.Single(s => s.Provider == "Shodan");
            Require(service.ObservedAtUtc == new DateTimeOffset(2020, 1, 2, 3, 4, 5, TimeSpan.Zero)
                && service.RetrievedAtUtc > service.ObservedAtUtc, "Observation time was confused with retrieval time.");
        }
    }
    await sql.ExecuteAsync("INSERT dbo.Host (IpAddress) VALUES ('192.0.2.3')");
    Require((await shodan.ClaimAsync(token))?.Target == "192.0.2.3", "New hosts were not picked up by Shodan.");
    Require((await nmap.ClaimAsync(token))?.Target == "192.0.2.3", "New hosts were not picked up by Nmap.");
    await sql.ExecuteAsync("""
        INSERT dbo.Request (SourceHostId, Target, Method, QueryString)
        SELECT HostId, '/fixture', 'GET', '?value=raw%26x' FROM dbo.Host WHERE IpAddress='192.0.2.1';
        """);
    var intelligence = new IntelligenceStore(new ConfigurationBuilder().AddInMemoryCollection(
        new Dictionary<string, string> { ["ConnectionStrings:HttpDb"] = connectionString }).Build());
    var inventory = await intelligence.CollectionAsync(null, "all", "requests", 0, token);
    Require(inventory.Total == 4 && inventory.Hosts.Count == 4, "Inventory omitted hosts without HTTP requests.");
    Require(inventory.Summary.TotalRequests == 1 && inventory.Summary.ShodanAvailable == 2
        && inventory.Summary.ShodanNoData == 1 && inventory.Summary.HostsWithCves == 2,
        "Collection metrics confused no-data, missing, or repeated CVE observations.");
    Require(inventory.Hosts[0].IpAddress == "192.0.2.1" && inventory.Hosts[0].Requests == 1, "Request sorting is incorrect.");
    Require(inventory.Hosts.Single(h => h.IpAddress == "192.0.2.1").CveCount == 2, "CVE identifiers were not deduplicated.");
    var cves = await intelligence.CollectionAsync("CVE-2025-0002", "cves", "cves", 99, token);
    Require(cves.Total == 2 && cves.Page == 0, "CVE search or out-of-range pagination is incorrect.");
    Require((await intelligence.CollectionAsync("%", "all", "last-seen", 0, token)).Total == 0, "Search wildcards were not literal.");
    Require((await intelligence.CollectionAsync(null, "no-data", "last-seen", 0, token)).Total == 1, "No-data filter is incorrect.");
    Require((await intelligence.CollectionAsync("fixture.test", "available", "last-seen", 0, token)).Total == 2,
        "Hostname search did not intersect with availability.");
    var evidenceJob = shodanClaims.Single(j => j.Target == "192.0.2.1");
    var otherHost = shodanClaims.Single(j => j.Target == "192.0.2.2").HostId;
    Require(await intelligence.EvidenceAsync(otherHost, evidenceJob.HostJobId, token) == null, "Evidence route crossed host IDs.");
    Require((await intelligence.EvidenceAsync(evidenceJob.HostId, evidenceJob.HostJobId, token)).Contains("\u96ea"),
        "Raw evidence route lost Unicode.");
    var requestPage = await intelligence.RequestsAsync(evidenceJob.HostId, null, token);
    Require(requestPage.Requests.Single().QueryString == "?value=raw%26x" && requestPage.NextCursor == null,
        "Traffic evidence changed the stored query.");
    Console.WriteLine("Passed: intelligence collection metrics, all-host inventory, CVE/hostname/literal search, sorting, paging, scoped raw evidence, and traffic.");

    await sql.ExecuteAsync("""
        INSERT dbo.Host (IpAddress) VALUES ('8.8.8.8'), ('192.168.1.56'), ('not-an-address');
        INSERT dbo.Request (SourceHostId, Target, Method)
        SELECT HostId, '/cleanup-fixture', 'GET' FROM dbo.Host
        WHERE IpAddress IN ('8.8.8.8','192.168.1.56','not-an-address');
        INSERT dbo.Header (RequestId, RequestPosition, Name, Value)
        SELECT RequestId, 0, 'X-Fixture', 'kept for public host' FROM dbo.Request
        WHERE CONVERT(nvarchar(max),Target)='/cleanup-fixture';
        INSERT dbo.HostJob (HostId, JobId, State)
        SELECT h.HostId, j.JobId, 1 FROM dbo.Host h CROSS JOIN dbo.Job j
        WHERE h.IpAddress IN ('8.8.8.8','192.168.1.56','not-an-address') AND j.Provider='Shodan';
        INSERT dbo.ReconEvidence (HostJobId, StatusCode, RetrievedAtUtc, ResponseJson)
        SELECT hj.HostJobId, 200, SYSUTCDATETIME(), N'{"fixture":true}'
        FROM dbo.HostJob hj JOIN dbo.Host h ON h.HostId=hj.HostId
        WHERE h.IpAddress IN ('8.8.8.8','192.168.1.56','not-an-address');
        INSERT dbo.Discovery (HostJobId, HostId, DiscoveryType, PortNumber, DiscoveryDetail)
        SELECT hj.HostJobId, h.HostId, 'Port', 443, 'tcp https fixture'
        FROM dbo.HostJob hj JOIN dbo.Host h ON h.HostId=hj.HostId
        WHERE h.IpAddress IN ('8.8.8.8','192.168.1.56','not-an-address');
        INSERT dbo.Hostname (HostId, Hostname) SELECT HostId, 'cleanup.example'
        FROM dbo.Host WHERE IpAddress IN ('8.8.8.8','192.168.1.56','not-an-address');
        """);
    var cleanup = new HostMaintenanceStore(new ConfigurationBuilder().AddInMemoryCollection(
        new Dictionary<string, string> { ["ConnectionStrings:HttpDb"] = connectionString }).Build(), analytics);
    var preview = await cleanup.PreviewAsync(token);
    Require(preview.Hosts.Count == 6 && preview.Hosts.All(h => h.IpAddress != "8.8.8.8"),
        "Cleanup preview must include malformed/documentation/local hosts but preserve public hosts.");
    Require(preview.Counts.Requests == 3 && preview.Counts.Headers == 2,
        "Cleanup preview omitted linked traffic or included public traffic.");
    var beforePurge = await analytics.GetAsync(new AnalysisWindow(null, null), true, token);
    Require(beforePurge.Snapshot.Sources.Count == 4, "Cleanup cache fixture did not load.");
    var privateId = preview.Hosts.Single(h => h.IpAddress == "192.168.1.56").HostId;
    var publicId = await sql.ExecuteScalarAsync<long>("SELECT HostId FROM dbo.Host WHERE IpAddress='8.8.8.8'");
    try
    {
        await cleanup.PurgeAsync(new[] { privateId, publicId }, token);
        throw new Exception("A crafted public-host purge was accepted.");
    }
    catch (ArgumentException) { }
    Require(await sql.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM dbo.Host") == 7, "Rejected purge changed hosts.");
    await sql.ExecuteAsync("""
        CREATE TABLE dbo.CleanupBlocker (HostId bigint REFERENCES dbo.Host(HostId));
        INSERT dbo.CleanupBlocker (HostId) VALUES (@HostId);
        """, new { HostId = privateId });
    try
    {
        await cleanup.PurgeAsync(new[] { privateId }, token);
        throw new Exception("Expected foreign-key failure did not occur.");
    }
    catch (SqlException exception) when (exception.Number == 547)
    {
        var afterFailure = await cleanup.PreviewAsync(token);
        Require(afterFailure.Counts == preview.Counts, "Failed purge did not roll back every dependent delete.");
    }
    await sql.ExecuteAsync("DROP TABLE dbo.CleanupBlocker");
    var running = await sql.QuerySingleAsync<ReconJob>("""
        SELECT hj.HostJobId, hj.HostId, h.IpAddress AS Target, hj.LeaseToken
        FROM dbo.HostJob hj JOIN dbo.Host h ON h.HostId=hj.HostId
        JOIN dbo.Job j ON j.JobId=hj.JobId WHERE h.IpAddress='192.0.2.3' AND j.Provider='Nmap'
        """);
    await sql.ExecuteAsync("INSERT dbo.Host (IpAddress) VALUES ('10.1.2.3')");
    var purged = await cleanup.PurgeAsync(preview.Hosts.Select(h => h.HostId).ToArray(), token);
    Require(purged == preview.Counts, "Purge result counts do not match actual linked records.");
    Require(await sql.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM dbo.Host") == 2,
        "Purge must not include non-public hosts added after the reviewed selection.");
    foreach (var table in new[] { "Request", "Header", "HostJob", "Discovery", "Hostname", "ReconEvidence" })
        Require(await sql.ExecuteScalarAsync<int>($"SELECT COUNT(*) FROM dbo.[{table}]") == 1,
            $"Cleanup left dependent records or deleted public evidence in {table}.");
    var afterPurge = await analytics.GetAsync(new AnalysisWindow(null, null), false, token);
    Require(afterPurge.Snapshot.Sources.Single().IpAddress == "8.8.8.8" && afterPurge.Snapshot.RequestCount == 1,
        "Behavior cache was not invalidated after purge.");
    Require((await cleanup.PurgeAsync(preview.Hosts.Select(h => h.HostId).ToArray(), token)).Hosts == 0,
        "Repeating a completed selection should not delete different hosts.");
    try
    {
        await nmap.CompleteAsync(running, empty, token);
        throw new Exception("A worker recreated evidence for a deleted host.");
    }
    catch (InvalidOperationException exception) when (exception.Message.Contains("lease was lost")) { }
    Console.WriteLine("Passed: non-public cleanup preview, public-host rejection, transactional rollback, exact reviewed selection, dependent deletion, cache invalidation, idempotency, and late worker fencing.");
    var appIndex = Array.IndexOf(args, "--app");
    if (appIndex >= 0) await VerifyMaintenanceHttpAsync(Path.GetFullPath(args[appIndex + 1]), connectionString);
    Console.WriteLine("Passed: migration/repeatability, concurrent provider queues, legacy and new hosts, lease fencing/retry, transactional Unicode/raw evidence, no-data, and atlas provenance.");
}
finally
{
    SqlConnection.ClearAllPools();
    if (created)
    {
        using var master = new SqlConnection(masterConnection);
        await master.ExecuteAsync($"ALTER DATABASE [{database}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{database}];");
        Console.WriteLine($"Removed owned database {database}. No external API or Nmap requests were sent.");
    }
}

static void Require(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static async Task VerifyMaintenanceHttpAsync(string application, string connectionString)
{
    if (!File.Exists(application)) throw new FileNotFoundException("Publish the analytics app before HTTP checks.", application);
    using var sql = new SqlConnection(connectionString);
    await sql.ExecuteAsync("""
        INSERT dbo.Request (SourceHostId, Target, Method)
        SELECT HostId, '/http-cleanup-fixture', 'GET' FROM dbo.Host WHERE IpAddress='10.1.2.3';
        INSERT dbo.Header (RequestId, RequestPosition, Name, Value)
        SELECT RequestId, 0, 'X-Fixture', 'delete with private request' FROM dbo.Request
        WHERE CONVERT(nvarchar(max),Target)='/http-cleanup-fixture';
        """);
    var publicId = await sql.ExecuteScalarAsync<long>("SELECT HostId FROM dbo.Host WHERE IpAddress='8.8.8.8'");
    using var process = new Process
    {
        StartInfo = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = Path.GetDirectoryName(application),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        },
        EnableRaisingEvents = true
    };
    foreach (var argument in new[] { application, "--urls", "http://127.0.0.1:0",
        "--ConnectionStrings:HttpDb", connectionString })
        process.StartInfo.ArgumentList.Add(argument);
    process.StartInfo.Environment["ASPNETCORE_ENVIRONMENT"] = "Production";
    var listening = new TaskCompletionSource<Uri>(TaskCreationOptions.RunContinuationsAsynchronously);
    var output = new System.Collections.Concurrent.ConcurrentQueue<string>();
    void Observe(object sender, DataReceivedEventArgs e)
    {
        if (e.Data == null) return;
        output.Enqueue(e.Data);
        const string prefix = "Now listening on: ";
        var index = e.Data.IndexOf(prefix, StringComparison.Ordinal);
        if (index >= 0 && Uri.TryCreate(e.Data[(index + prefix.Length)..].Trim(), UriKind.Absolute, out var address))
            listening.TrySetResult(address);
    }
    process.OutputDataReceived += Observe;
    process.ErrorDataReceived += Observe;
    process.Exited += (_, _) => listening.TrySetException(new InvalidOperationException("Owned analytics app exited before readiness."));
    var started = false;
    try
    {
        started = process.Start();
        process.BeginOutputReadLine(); process.BeginErrorReadLine();
        using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        { BaseAddress = await listening.Task.WaitAsync(TimeSpan.FromSeconds(30)), Timeout = TimeSpan.FromSeconds(30) };
        var preview = await client.GetFromJsonAsync<HostCleanupPreview>("/api/intelligence/non-public-hosts");
        Require(preview.Hosts.Single().IpAddress == "10.1.2.3" && preview.Counts.Requests == 1,
            "HTTP preview returned incorrect candidates or counts.");
        using (var before = JsonDocument.Parse(await client.GetStringAsync("/api/snapshot")))
            Require(before.RootElement.GetProperty("sources").GetArrayLength() == 2, "HTTP cache fixture did not load.");
        using (var rejected = await client.PostAsJsonAsync("/api/intelligence/non-public-hosts/purge",
            new { hostIds = new[] { publicId } }))
            Require(rejected.StatusCode == HttpStatusCode.BadRequest, "HTTP purge accepted a public address.");
        using (var rejected = await client.PostAsJsonAsync("/api/intelligence/non-public-hosts/purge",
            new { hostIds = Array.Empty<long>() }))
            Require(rejected.StatusCode == HttpStatusCode.BadRequest, "Empty HTTP selection must not mean all hosts.");
        using (var form = await client.PostAsync("/api/intelligence/non-public-hosts/purge",
            new StringContent($"hostIds={preview.Hosts[0].HostId}", Encoding.UTF8, "application/x-www-form-urlencoded")))
            Require(form.StatusCode == HttpStatusCode.UnsupportedMediaType, "Purge must require JSON, not a cross-site HTML form.");
        using (var response = await client.PostAsJsonAsync("/api/intelligence/non-public-hosts/purge",
            new { hostIds = preview.Hosts.Select(host => host.HostId).ToArray() }))
        {
            Require(response.IsSuccessStatusCode, "HTTP purge failed.");
            var counts = await response.Content.ReadFromJsonAsync<HostPurgeCounts>();
            Require(counts.Hosts == 1 && counts.Requests == 1 && counts.Headers == 1,
                "HTTP purge did not delete the reviewed host and its linked traffic.");
        }
        using (var after = JsonDocument.Parse(await client.GetStringAsync("/api/snapshot")))
            Require(after.RootElement.GetProperty("sources").GetArrayLength() == 1
                && after.RootElement.GetProperty("requestCount").GetInt64() == 1, "HTTP purge left a stale cached snapshot.");
        Require((await client.GetFromJsonAsync<HostCleanupPreview>("/api/intelligence/non-public-hosts")).Hosts.Count == 0,
            "HTTP preview retained a purged host.");
        Console.WriteLine("Passed: published HTTP cleanup preview, public/empty selection rejection, JSON-only mutation, linked deletion and cache regeneration.");
    }
    catch
    {
        Console.Error.WriteLine(string.Join(Environment.NewLine, output));
        throw;
    }
    finally
    {
        if (started)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            Console.WriteLine($"Stopped owned analytics process {process.Id}.");
        }
    }
}

sealed class FixtureHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        var ip = Uri.UnescapeDataString(request.RequestUri.AbsolutePath.Split('/').Last());
        var missing = ip == "192.0.2.2";
        var json = missing ? """{"error":"No information available for that IP."}""" : JsonSerializer.Serialize(new
        {
            ip_str = ip,
            hostnames = new[] { "fixture.test" },
            org = "Example",
            country_name = "Example country",
            asn = "AS64500",
            vulns = new[] { "CVE-2025-0001" },
            data = new[] { new { port = 443, transport = "tcp", _shodan = new { module = "https" },
                timestamp = "2020-01-02T03:04:05", data = new string('x', 12000) + "\u96ea",
                vulns = new Dictionary<string, object> { ["CVE-2025-0001"] = new { cvss = 0, verified = false },
                    ["CVE-2025-0002"] = new { cvss = 9.8, verified = true } } } }
        }).Replace("\\u96EA", "\u96ea");
        return Task.FromResult(new HttpResponseMessage(missing ? HttpStatusCode.NotFound : HttpStatusCode.OK)
        { Content = new StringContent(json) });
    }
}
