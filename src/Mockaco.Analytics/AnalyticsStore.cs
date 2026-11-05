using System.Data;
using System.Data.SqlClient;
using Dapper;

namespace Mockaco.Analytics;

public sealed class AnalyticsStore(IConfiguration configuration) : IDisposable
{
    private readonly string _connectionString = configuration.GetConnectionString("HttpDb")
        ?? "Data Source=localhost;Initial Catalog=HttpDb;Integrated Security=True;Encrypt=False;";
    private readonly SemaphoreSlim _gate = new(1);
    private (AnalysisWindow Window, BehaviorAnalysis Analysis)? _cached;

    public async Task<BehaviorAnalysis> GetAsync(AnalysisWindow window, bool refresh, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (!refresh && _cached is { } cached && cached.Window == window) return cached.Analysis;
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            using var results = await connection.QueryMultipleAsync(new CommandDefinition("""
                SELECT r.SourceHostId AS HostId, h.IpAddress, r.Method,
                    CONVERT(nvarchar(max), r.Target) AS Target, COUNT_BIG(*) AS Count,
                    MIN(r.CreatedDate) AS FirstSeen, MAX(r.CreatedDate) AS LastSeen
                FROM dbo.Request r JOIN dbo.Host h ON h.HostId = r.SourceHostId
                WHERE (@From IS NULL OR r.CreatedDate >= @From)
                    AND (@Before IS NULL OR r.CreatedDate < @Before)
                GROUP BY r.SourceHostId, h.IpAddress, r.Method,
                    CONVERT(nvarchar(max), r.Target) COLLATE Latin1_General_100_BIN2,
                    CONVERT(nvarchar(max), r.Target)
                OPTION (RECOMPILE);
                SELECT HostId, PortNumber, CONVERT(nvarchar(max), DiscoveryDetail) AS Detail, DiscoveryType
                FROM dbo.Discovery;
                SELECT COUNT_BIG(*) FROM dbo.Request r
                WHERE NOT EXISTS (SELECT 1 FROM dbo.Host h WHERE h.HostId = r.SourceHostId)
                    AND (@From IS NULL OR r.CreatedDate >= @From)
                    AND (@Before IS NULL OR r.CreatedDate < @Before)
                OPTION (RECOMPILE);
                """, Parameters(window), commandTimeout: 120, cancellationToken: cancellationToken));
            var requests = (await results.ReadAsync<RequestAggregate>()).ToArray();
            var observations = (await results.ReadAsync<ServiceObservation>()).ToArray();
            var unattributed = await results.ReadSingleAsync<long>();
            var analysis = BehaviorAnalysis.Build(requests, observations, cancellationToken);
            analysis.SetUnattributedRequests(unattributed);
            _cached = (window, analysis);
            return analysis;
        }
        finally { _gate.Release(); }
    }

    public async Task<SourceDetail?> SourceAsync(long hostId, AnalysisWindow window, long? cursor,
        CancellationToken cancellationToken)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        var parameters = Parameters(window);
        parameters.Add("HostId", hostId);
        parameters.Add("Cursor", cursor);
        using var results = await connection.QueryMultipleAsync(new CommandDefinition("""
            SELECT IpAddress FROM dbo.Host WHERE HostId = @HostId;
            SELECT DISTINCT Hostname FROM dbo.Hostname WHERE HostId = @HostId ORDER BY Hostname;
            SELECT d.PortNumber, CONVERT(nvarchar(max), d.DiscoveryDetail) AS Detail, d.HostJobId,
                hj.UpdatedAt AS JobUpdatedAt, j.Provider,
                CAST(d.ObservedAtUtc AS datetimeoffset) AS ObservedAtUtc,
                CAST(e.RetrievedAtUtc AS datetimeoffset) AS RetrievedAtUtc
            FROM dbo.Discovery d JOIN dbo.HostJob hj ON hj.HostJobId = d.HostJobId
            JOIN dbo.Job j ON j.JobId = hj.JobId
            LEFT JOIN dbo.ReconEvidence e ON e.HostJobId = hj.HostJobId
            WHERE d.HostId = @HostId AND d.DiscoveryType = 'Port'
            ORDER BY d.PortNumber, d.DiscoveryId;
            SELECT hj.HostJobId, hj.State, hj.UpdatedAt, hj.LastError, j.Provider, e.StatusCode,
                CAST(e.RetrievedAtUtc AS datetimeoffset) AS RetrievedAtUtc
            FROM dbo.HostJob hj JOIN dbo.Job j ON j.JobId = hj.JobId
            LEFT JOIN dbo.ReconEvidence e ON e.HostJobId = hj.HostJobId
            WHERE hj.HostId = @HostId ORDER BY hj.HostJobId DESC;
            SELECT r.SourceHostId AS HostId, h.IpAddress, r.Method,
                CONVERT(nvarchar(max), r.Target) AS Target, COUNT_BIG(*) AS Count,
                MIN(r.CreatedDate) AS FirstSeen, MAX(r.CreatedDate) AS LastSeen
            FROM dbo.Request r JOIN dbo.Host h ON h.HostId = r.SourceHostId
            WHERE r.SourceHostId = @HostId AND (@From IS NULL OR r.CreatedDate >= @From)
                AND (@Before IS NULL OR r.CreatedDate < @Before)
            GROUP BY r.SourceHostId, h.IpAddress, r.Method,
                CONVERT(nvarchar(max), r.Target) COLLATE Latin1_General_100_BIN2,
                CONVERT(nvarchar(max), r.Target)
            ORDER BY Count DESC;
            SELECT TOP (101) RequestId, Method, CONVERT(nvarchar(max), Target) AS Target,
                QueryString, TargetHost, CreatedDate FROM dbo.Request
            WHERE SourceHostId = @HostId AND (@From IS NULL OR CreatedDate >= @From)
                AND (@Before IS NULL OR CreatedDate < @Before)
                AND (@Cursor IS NULL OR RequestId < @Cursor)
            ORDER BY RequestId DESC;
            """, parameters, commandTimeout: 120, cancellationToken: cancellationToken));
        var ipAddress = await results.ReadSingleOrDefaultAsync<string>();
        var hostnames = (await results.ReadAsync<string>()).ToArray();
        var services = (await results.ReadAsync<CapturedService>()).ToArray();
        var jobs = (await results.ReadAsync<ReconState>()).ToArray();
        var paths = (await results.ReadAsync<RequestAggregate>()).ToArray();
        var requests = (await results.ReadAsync<CapturedRequest>()).ToArray();
        return ipAddress is null ? null : new(hostId, ipAddress, hostnames, services, jobs, paths,
            requests.Take(100).ToArray(), requests.Length > 100 ? requests[99].RequestId : null);
    }

    public async Task InvalidateAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try { _cached = null; }
        finally { _gate.Release(); }
    }

    private static DynamicParameters Parameters(AnalysisWindow window)
    {
        var parameters = new DynamicParameters();
        parameters.Add("From", window.From, DbType.DateTime2);
        parameters.Add("Before", window.Before, DbType.DateTime2);
        return parameters;
    }

    public void Dispose() => _gate.Dispose();
}
