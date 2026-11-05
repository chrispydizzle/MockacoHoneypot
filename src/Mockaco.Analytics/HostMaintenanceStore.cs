using System.Data.SqlClient;
using System.Text.Json;
using Dapper;

namespace Mockaco.Analytics;

public sealed class HostMaintenanceStore(IConfiguration configuration, AnalyticsStore analytics)
{
    private readonly string _connectionString = configuration.GetConnectionString("HttpDb")
        ?? "Data Source=localhost;Initial Catalog=HttpDb;Integrated Security=True;Encrypt=False;";

    public async Task<HostCleanupPreview> PreviewAsync(CancellationToken cancellationToken)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        var addresses = await connection.QueryAsync<(long HostId, string IpAddress)>(new CommandDefinition(
            "SELECT HostId, IpAddress FROM dbo.Host ORDER BY HostId;", cancellationToken: cancellationToken));
        var hosts = addresses.Select(host => (host, Reason: HostAddressPolicy.NonPublicReason(host.IpAddress)))
            .Where(item => item.Reason != null)
            .Select(item => new NonPublicHost(item.host.HostId, item.host.IpAddress, item.Reason!)).ToArray();
        var counts = await connection.QuerySingleAsync<HostPurgeCounts>(new CommandDefinition("""
            CREATE TABLE #Hosts (HostId bigint PRIMARY KEY);
            INSERT #Hosts SELECT CONVERT(bigint,[value]) FROM OPENJSON(@HostIds);
            SELECT r.RequestId INTO #Requests FROM dbo.Request r JOIN #Hosts h ON h.HostId=r.SourceHostId;
            SELECT hj.HostJobId INTO #Jobs FROM dbo.HostJob hj JOIN #Hosts h ON h.HostId=hj.HostId;
            SELECT (SELECT COUNT_BIG(*) FROM #Hosts) AS Hosts,
                (SELECT COUNT_BIG(*) FROM #Requests) AS Requests,
                (SELECT COUNT_BIG(*) FROM dbo.Header WHERE RequestId IN (SELECT RequestId FROM #Requests)) AS Headers,
                (SELECT COUNT_BIG(*) FROM #Jobs) AS Jobs,
                (SELECT COUNT_BIG(*) FROM dbo.Discovery WHERE HostId IN (SELECT HostId FROM #Hosts)
                    OR HostJobId IN (SELECT HostJobId FROM #Jobs)) AS Discoveries,
                (SELECT COUNT_BIG(*) FROM dbo.Hostname WHERE HostId IN (SELECT HostId FROM #Hosts)) AS Hostnames,
                (SELECT COUNT_BIG(*) FROM dbo.ReconEvidence WHERE HostJobId IN (SELECT HostJobId FROM #Jobs)) AS Evidence;
            """, new { HostIds = JsonSerializer.Serialize(hosts.Select(host => host.HostId)) },
            commandTimeout: 120, cancellationToken: cancellationToken));
        return new(hosts, counts);
    }

    public async Task<HostPurgeCounts> PurgeAsync(long[]? hostIds, CancellationToken cancellationToken)
    {
        if (hostIds is not { Length: > 0 } || hostIds.Any(id => id <= 0))
            throw new ArgumentException("Select the non-public hosts to purge.");
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        // Parameterized batches scope temp tables to sp_executesql; create shared tables outside that scope.
        await connection.ExecuteAsync(new CommandDefinition("""
            CREATE TABLE #Hosts (HostId bigint PRIMARY KEY);
            CREATE TABLE #Jobs (HostJobId bigint PRIMARY KEY);
            """, transaction: transaction, cancellationToken: cancellationToken));
        var selected = await connection.QueryAsync<(long HostId, string IpAddress)>(new CommandDefinition("""
            DECLARE @LockResult int;
            EXEC @LockResult = sys.sp_getapplock @Resource='Mockaco.Recon.Claim',
                @LockMode='Exclusive', @LockOwner='Transaction', @LockTimeout=10000;
            IF @LockResult<0 THROW 50001, 'Could not acquire recon claim lock', 1;
            INSERT #Hosts SELECT DISTINCT CONVERT(bigint,[value]) FROM OPENJSON(@HostIds);
            INSERT #Jobs SELECT hj.HostJobId FROM dbo.HostJob hj WITH (UPDLOCK,HOLDLOCK)
                JOIN #Hosts h ON h.HostId=hj.HostId;
            SELECT h.HostId, h.IpAddress FROM dbo.Host h WITH (XLOCK,HOLDLOCK)
                JOIN #Hosts selected ON selected.HostId=h.HostId;
            """, new { HostIds = JsonSerializer.Serialize(hostIds) }, transaction,
            commandTimeout: 120, cancellationToken: cancellationToken));
        if (selected.Any(host => HostAddressPolicy.NonPublicReason(host.IpAddress) == null))
            throw new ArgumentException("The selection includes a public address. Review the cleanup list again.");
        var counts = await connection.QuerySingleAsync<HostPurgeCounts>(new CommandDefinition("""
            SELECT r.RequestId INTO #Requests FROM dbo.Request r WITH (UPDLOCK,HOLDLOCK)
                JOIN #Hosts h ON h.HostId=r.SourceHostId;
            DELETE FROM dbo.Header WHERE RequestId IN (SELECT RequestId FROM #Requests);
            DECLARE @Headers bigint=ROWCOUNT_BIG();
            DELETE FROM dbo.Request WHERE RequestId IN (SELECT RequestId FROM #Requests);
            DECLARE @Requests bigint=ROWCOUNT_BIG();
            DELETE FROM dbo.Discovery WHERE HostId IN (SELECT HostId FROM #Hosts)
                OR HostJobId IN (SELECT HostJobId FROM #Jobs);
            DECLARE @Discoveries bigint=ROWCOUNT_BIG();
            DELETE FROM dbo.ReconEvidence WHERE HostJobId IN (SELECT HostJobId FROM #Jobs);
            DECLARE @Evidence bigint=ROWCOUNT_BIG();
            DELETE FROM dbo.Hostname WHERE HostId IN (SELECT HostId FROM #Hosts);
            DECLARE @Hostnames bigint=ROWCOUNT_BIG();
            DELETE FROM dbo.HostJob WHERE HostJobId IN (SELECT HostJobId FROM #Jobs);
            DECLARE @Jobs bigint=ROWCOUNT_BIG();
            DELETE FROM dbo.Host WHERE HostId IN (SELECT HostId FROM #Hosts);
            SELECT ROWCOUNT_BIG() AS Hosts, @Requests AS Requests, @Headers AS Headers,
                @Jobs AS Jobs, @Discoveries AS Discoveries, @Hostnames AS Hostnames, @Evidence AS Evidence;
            """, transaction: transaction, commandTimeout: 120, cancellationToken: cancellationToken));
        cancellationToken.ThrowIfCancellationRequested();
        try { transaction.Commit(); }
        finally
        {
            // A disconnected HTTP caller must not leave pre-purge analysis cached.
            await analytics.InvalidateAsync(CancellationToken.None);
        }
        return counts;
    }
}
