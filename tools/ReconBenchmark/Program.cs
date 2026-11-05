using System.Collections.Concurrent;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Dapper;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Mockaco.Recon;

var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
var fullProfile = args.Contains("--full-profile");
var verifyOnly = args.Contains("--verify-only");
var repetitions = 2;
var count = 16;
string Value(string flag, string fallback)
{
    var index = Array.IndexOf(args, flag);
    return index < 0 ? fallback : args[index + 1];
}
repetitions = int.Parse(Value("--repetitions", "2"));
count = int.Parse(Value("--targets", "16"));
if (count < 1 || count > 254 || repetitions < 1) throw new ArgumentException("Use 1-254 targets and positive repetitions.");
var outputPath = Path.GetFullPath(Value("--output", Path.Combine(root, "tools", "ReconBenchmark", "results.json")));
var database = "MockacoReconBenchmark_" + Guid.NewGuid().ToString("N");
var masterConnection = Value("--sql", "Data Source=localhost;Initial Catalog=master;Integrated Security=True;TrustServerCertificate=True;");
var builder = new SqlConnectionStringBuilder(masterConnection) { InitialCatalog = database };
var options = new ReconOptions { ConnectionString = builder.ConnectionString, Ports = fullProfile ? null : "8080,8081" };
var settings = Options.Create(options);
var store = new SqlReconJobStore(settings);
using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; cancellation.Cancel(); };
var listeners = new List<TcpListener>();
var servers = new List<Task>();
var handlers = new ConcurrentBag<Task>();
var created = false;
var results = new List<object>();
var targets = Enumerable.Range(1, count).Select(i => $"127.77.0.{i}").ToArray();
using var logs = LoggerFactory.Create(logging => logging.AddSimpleConsole().SetMinimumLevel(LogLevel.Warning));
var scanner = new NmapScanner(settings);
try
{
    using (var master = new SqlConnection(masterConnection))
    {
        await master.ExecuteAsync($"CREATE DATABASE [{database}]");
        created = true;
    }
    using var sql = new SqlConnection(options.ConnectionString);
    await sql.OpenAsync(cancellation.Token);
    foreach (var file in new[] { "Host.sql", "Job.sql", "HostJob.sql", "Discovery.sql", "dbo.Hostname.sql", "ReconEvidence.sql" })
        await sql.ExecuteAsync(await File.ReadAllTextAsync(Path.Combine(root, "HttpLog", file)));
    // Verify the existing-database migration too, including repeatability.
    await sql.ExecuteAsync("ALTER TABLE dbo.HostJob DROP COLUMN LeaseToken, LeaseUntil, LastError");
    var migration = await File.ReadAllTextAsync(Path.Combine(root, "HttpLog", "Migrations", "001-ReconLeases.sql"));
    await sql.ExecuteAsync(migration);
    await sql.ExecuteAsync(migration);
    await sql.ExecuteAsync("INSERT dbo.Job (Name) VALUES ('Benchmark')");
    foreach (var target in targets)
    {
        await sql.ExecuteAsync("INSERT dbo.Host (IpAddress) VALUES (@Target)", new { Target = target });
        var listener = new TcpListener(IPAddress.Parse(target), 8080);
        listener.Start();
        listeners.Add(listener);
        servers.Add(ServeAsync(listener, cancellation.Token));
    }
    Console.WriteLine($"Isolated database: {database}; targets: {count}; ports: {options.Ports ?? "top 5000"}; -sV --version-all -O");
    await VerifyClaimsAsync(sql);
    await VerifyCancellationAsync();
    Console.WriteLine("SQL claims, migration, stale-lease fencing, failure states, and real process cancellation passed.");
    var warmup = await scanner.ScanAsync(targets[0], cancellation.Token);
    VerifyScan(warmup);
    Console.WriteLine("Warmup found owned HTTP service; closed-port exclusion verified.");

    for (int repetition = 1; !verifyOnly && repetition <= repetitions; repetition++)
    {
        foreach (var workers in repetition % 2 == 1 ? new[] { 2, 8, 4, 16 } : new[] { 16, 4, 8, 2 })
        {
            await sql.ExecuteAsync("DELETE dbo.Discovery; DELETE dbo.Hostname; DELETE dbo.HostJob;");
            options.Workers = workers;
            var measured = new MeasuredScanner(scanner);
            using var worker = new ReconWorker(store, measured, settings, logs.CreateLogger<ReconWorker>());
            var clock = Stopwatch.StartNew();
            try
            {
                await worker.StartAsync(cancellation.Token);
                while (await sql.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM dbo.HostJob WHERE State IN (1,3)") < count)
                {
                    cancellation.Token.ThrowIfCancellationRequested();
                    await Task.Delay(100, cancellation.Token);
                }
            }
            finally
            {
                await worker.StopAsync(CancellationToken.None);
            }
            clock.Stop();
            var failed = await sql.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM dbo.HostJob WHERE State = 3");
            var missing = await sql.ExecuteScalarAsync<int>(@"
SELECT COUNT(*) FROM dbo.Host h WHERE NOT EXISTS
(SELECT 1 FROM dbo.Discovery d WHERE d.HostId = h.HostId AND d.PortNumber = 8080 AND d.DiscoveryDetail LIKE '%http%')");
            var closed = await sql.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM dbo.Discovery WHERE PortNumber = 8081");
            var duplicate = await sql.ExecuteScalarAsync<int>(
                "SELECT COUNT(*) FROM (SELECT HostId, JobId FROM dbo.HostJob GROUP BY HostId, JobId HAVING COUNT(*) > 1) d");
            var latencies = measured.Durations.Order().ToArray();
            var result = new
            {
                Repetition = repetition, Workers = workers, Targets = count,
                Seconds = Math.Round(clock.Elapsed.TotalSeconds, 3),
                HostsPerMinute = Math.Round((count - failed) * 60 / clock.Elapsed.TotalSeconds, 2),
                P95ScanSeconds = latencies.Length == 0 ? 0 : latencies[(int)Math.Ceiling(latencies.Length * .95) - 1],
                PeakProcesses = measured.Peak, ScanStarts = measured.Starts,
                Failed = failed, MissingHttp = missing, ClosedPortDiscoveries = closed, DuplicateClaims = duplicate
            };
            results.Add(result);
            Console.WriteLine(JsonSerializer.Serialize(result));
            await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new
            {
                Profile = options.Ports == null ? "Production: top 5000, -Pn -sV --version-all -O, 10m host timeout" :
                    "Controlled loopback: ports 8080,8081; -Pn -sV --version-all -O, 10m host timeout",
                TimestampUtc = DateTime.UtcNow,
                OperatingSystem = Environment.OSVersion.VersionString,
                Runtime = Environment.Version.ToString(),
                LogicalProcessors = Environment.ProcessorCount,
                Results = results
            }, new JsonSerializerOptions { WriteIndented = true }));
            if (failed != 0 || missing != 0 || closed != 0 || duplicate != 0 || measured.Starts != count)
                throw new InvalidOperationException("Benchmark correctness check failed; see results and logged scan errors.");
        }
    }
}
finally
{
    cancellation.Cancel();
    foreach (var listener in listeners) listener.Stop();
    try
    {
        await Task.WhenAll(servers);
        await Task.WhenAll(handlers);
    }
    finally
    {
        SqlConnection.ClearAllPools();
        if (created)
        {
            using var master = new SqlConnection(masterConnection);
            await master.ExecuteAsync($"ALTER DATABASE [{database}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{database}];");
            Console.WriteLine($"Removed owned benchmark database {database}.");
        }
    }
}

void VerifyScan(ReconScan scan)
{
    if (!scan.Ports.Any(p => p.Number == 8080 && p.Detail.Contains("http")) || scan.Ports.Any(p => p.Number == 8081))
        throw new InvalidOperationException("Owned open/closed HTTP controls did not match Nmap results.");
}

async Task VerifyClaimsAsync(SqlConnection sql)
{
    var claims = (await Task.WhenAll(Enumerable.Range(0, count * 2).Select(_ => store.ClaimAsync(cancellation.Token))))
        .Where(job => job != null).ToArray();
    if (claims.Length != count || claims.Select(job => job.HostJobId).Distinct().Count() != count)
        throw new InvalidOperationException("Concurrent claims duplicated or lost work.");
    foreach (var job in claims) await store.FailAsync(job, "Benchmark cancellation", true, cancellation.Token);
    var abandoned = await store.ClaimAsync(cancellation.Token);
    await sql.ExecuteAsync("UPDATE dbo.HostJob SET LeaseUntil = DATEADD(second, -1, SYSUTCDATETIME()) WHERE HostJobId = @HostJobId", abandoned);
    var reclaimed = await store.ClaimAsync(cancellation.Token);
    if (reclaimed.HostJobId != abandoned.HostJobId || reclaimed.LeaseToken == abandoned.LeaseToken)
        throw new InvalidOperationException("Expired lease was not reclaimed.");
    try
    {
        await store.CompleteAsync(abandoned, new ReconScan(Array.Empty<string>(), Array.Empty<ReconPort>()), cancellation.Token);
        throw new Exception("Stale owner unexpectedly committed results.");
    }
    catch (InvalidOperationException exception) when (exception.Message.Contains("lease was lost")) { }
    await store.FailAsync(abandoned, "Old owner", true, cancellation.Token);
    var token = await sql.ExecuteScalarAsync<Guid>("SELECT LeaseToken FROM dbo.HostJob WHERE HostJobId = @HostJobId", reclaimed);
    if (token != reclaimed.LeaseToken) throw new InvalidOperationException("Old owner overwrote new claim.");
    try
    {
        await store.CompleteAsync(reclaimed, new ReconScan(
            new[] { "benchmark.rollback", new string('x', 501) }, Array.Empty<ReconPort>()), cancellation.Token);
        throw new InvalidOperationException("Expected SQL truncation failure did not occur.");
    }
    catch (SqlException)
    {
        if (await sql.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM dbo.Hostname") != 0)
            throw new InvalidOperationException("Failed persistence did not roll back partial results.");
    }
    await store.FailAsync(reclaimed, "Expected failure", false, cancellation.Token);
    if (await sql.ExecuteScalarAsync<int>("SELECT State FROM dbo.HostJob WHERE HostJobId = @HostJobId", reclaimed) != 3)
        throw new InvalidOperationException("Failed scan was recorded as successful.");
    var next = await store.ClaimAsync(cancellation.Token);
    if (next != null && next.HostJobId == reclaimed.HostJobId)
        throw new InvalidOperationException("Terminal failed job was automatically retried.");
    await sql.ExecuteAsync("DELETE dbo.HostJob");
}

async Task VerifyCancellationAsync()
{
    using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token);
    stop.CancelAfter(TimeSpan.FromMilliseconds(250));
    try
    {
        await new NmapScanner(Options.Create(new ReconOptions())).ScanAsync(targets[0], stop.Token);
        throw new InvalidOperationException("Cancellation probe finished before cancellation.");
    }
    catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    try
    {
        await new NmapScanner(Options.Create(new ReconOptions { ProcessTimeoutSeconds = 1 }))
            .ScanAsync(targets[0], cancellation.Token);
        throw new InvalidOperationException("Process deadline did not fire.");
    }
    catch (TimeoutException) { }
}

async Task ServeAsync(TcpListener listener, CancellationToken token)
{
    try
    {
        while (!token.IsCancellationRequested)
        {
            var client = await listener.AcceptTcpClientAsync(token);
            handlers.Add(RespondAsync(client, token));
        }
    }
    catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    catch (SocketException) when (token.IsCancellationRequested) { }
    catch (ObjectDisposedException) when (token.IsCancellationRequested) { }
}

async Task RespondAsync(TcpClient client, CancellationToken token)
{
    using (client)
    {
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TimeSpan.FromSeconds(5));
            var stream = client.GetStream();
            var bytes = await stream.ReadAsync(new byte[4096], deadline.Token);
            if (bytes == 0) return;
            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nServer: MockacoBenchmark/1.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"), deadline.Token);
        }
        catch (OperationCanceledException) { }
        catch (IOException exception) when (exception.InnerException is SocketException) { }
    }
}

sealed class MeasuredScanner(INmapScanner scanner) : INmapScanner
{
    private int active;
    private int peak;
    private int starts;
    public int Peak => peak;
    public int Starts => starts;
    public ConcurrentBag<double> Durations { get; } = new();
    public async Task<ReconScan> ScanAsync(string target, CancellationToken token)
    {
        Interlocked.Increment(ref starts);
        var current = Interlocked.Increment(ref active);
        int previous;
        do { previous = peak; } while (current > previous && Interlocked.CompareExchange(ref peak, current, previous) != previous);
        var clock = Stopwatch.StartNew();
        try { return await scanner.ScanAsync(target, token); }
        finally
        {
            Durations.Add(clock.Elapsed.TotalSeconds);
            Interlocked.Decrement(ref active);
        }
    }
}
