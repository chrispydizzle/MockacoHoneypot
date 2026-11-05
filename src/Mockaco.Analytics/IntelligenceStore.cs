using System.Data.SqlClient;
using Dapper;

namespace Mockaco.Analytics;

public sealed class IntelligenceStore(IConfiguration configuration)
{
    private readonly string _connectionString = configuration.GetConnectionString("HttpDb")
        ?? "Data Source=localhost;Initial Catalog=HttpDb;Integrated Security=True;Encrypt=False;";

    public async Task<IntelligenceCollection> CollectionAsync(string? query, string status, string sort, int page,
        CancellationToken cancellationToken)
    {
        if (page < 0) throw new ArgumentException("Page must be zero or greater.");
        var predicate = status switch
        {
            "all" => "1=1",
            "available" => "i.StatusCode=200",
            "no-data" => "i.StatusCode=404",
            "unqueried" => "i.StatusCode IS NULL",
            "pending" => "i.ShodanState IN (0,2)",
            "failed" => "i.ShodanState=3",
            "cves" => "i.CveCount>0",
            "services" => "i.PortCount>0",
            _ => throw new ArgumentException("Unknown intelligence status filter.")
        };
        var order = sort switch
        {
            "last-seen" => "LastSeen DESC",
            "requests" => "Requests DESC",
            "ports" => "PortCount DESC",
            "cves" => "CveCount DESC",
            _ => throw new ArgumentException("Unknown intelligence sort.")
        };
        var search = (query ?? "").Trim().Replace("[", "[[]").Replace("%", "[%]").Replace("_", "[_]");
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        using var results = await connection.QueryMultipleAsync(new CommandDefinition($$"""
            SET NOCOUNT ON;
            WITH RequestTotals AS (
                SELECT SourceHostId, COUNT_BIG(*) AS Requests, MAX(CreatedDate) AS LastSeen
                FROM dbo.Request WHERE SourceHostId IS NOT NULL GROUP BY SourceHostId
            ), PortTotals AS (
                SELECT HostId, COUNT(DISTINCT PortNumber) AS PortCount
                FROM dbo.Discovery WHERE DiscoveryType='Port' GROUP BY HostId
            ), Evidence AS (
                SELECT hj.HostId, e.StatusCode, e.RetrievedAtUtc,
                    CASE WHEN ISJSON(e.ResponseJson)=1 THEN e.ResponseJson ELSE N'{}' END AS Json,
                    ROW_NUMBER() OVER (PARTITION BY hj.HostId ORDER BY e.RetrievedAtUtc DESC, e.HostJobId DESC) AS Position
                FROM dbo.ReconEvidence e JOIN dbo.HostJob hj ON hj.HostJobId=e.HostJobId
                JOIN dbo.Job j ON j.JobId=hj.JobId WHERE j.Provider=N'Shodan'
            )
            SELECT h.HostId, h.IpAddress, ISNULL(r.Requests,0) AS Requests, r.LastSeen,
                ISNULL(p.PortCount,0) AS PortCount, JSON_VALUE(e.Json,'$.org') AS Organization,
                JSON_VALUE(e.Json,'$.isp') AS Isp, JSON_VALUE(e.Json,'$.asn') AS Asn,
                JSON_VALUE(e.Json,'$.country_name') AS Country, JSON_VALUE(e.Json,'$.city') AS City,
                JSON_VALUE(e.Json,'$.os') AS OperatingSystem, ISNULL(v.CveCount,0) AS CveCount,
                e.StatusCode, sj.State AS ShodanState, CAST(e.RetrievedAtUtc AS datetimeoffset) AS RetrievedAtUtc,
                JSON_VALUE(e.Json,'$.last_update') AS ObservedAtUtc,
                JSON_QUERY(e.Json,'$.domains') AS Domains, v.Cves,
                CONVERT(bit, CASE WHEN EXISTS (
                    SELECT 1 FROM dbo.HostJob hj JOIN dbo.Job j ON j.JobId=hj.JobId
                    WHERE hj.HostId=h.HostId AND j.Provider=N'Nmap' AND hj.State=1
                ) THEN 1 ELSE 0 END) AS NmapCompleted
            INTO #Inventory
            FROM dbo.Host h
            LEFT JOIN RequestTotals r ON r.SourceHostId=h.HostId
            LEFT JOIN PortTotals p ON p.HostId=h.HostId
            LEFT JOIN Evidence e ON e.HostId=h.HostId AND e.Position=1
            OUTER APPLY (
                SELECT TOP(1) hj.State FROM dbo.HostJob hj JOIN dbo.Job j ON j.JobId=hj.JobId
                WHERE hj.HostId=h.HostId AND j.Provider=N'Shodan' ORDER BY hj.UpdatedAt DESC, hj.HostJobId DESC
            ) sj
            OUTER APPLY (
                SELECT COUNT(*) AS CveCount, STRING_AGG(CONVERT(nvarchar(max), Cve),N' ') AS Cves FROM (
                    SELECT CASE WHEN [type]=1 THEN [value] ELSE [key] END AS Cve FROM OPENJSON(e.Json,'$.vulns')
                    UNION
                    SELECT CASE WHEN v.[type]=1 THEN v.[value] ELSE v.[key] END
                    FROM OPENJSON(e.Json,'$.data') b CROSS APPLY OPENJSON(b.value,'$.vulns') v
                ) ids WHERE Cve LIKE N'CVE-%'
            ) v;
            SELECT COUNT_BIG(*) AS TotalHosts, (SELECT COUNT_BIG(*) FROM dbo.Request) AS TotalRequests,
                (SELECT COUNT_BIG(*) FROM dbo.Discovery WHERE DiscoveryType='Port') AS ServiceObservations,
                COUNT_BIG(CASE WHEN StatusCode=200 THEN 1 END) AS ShodanAvailable,
                COUNT_BIG(CASE WHEN StatusCode=404 THEN 1 END) AS ShodanNoData,
                COUNT_BIG(CASE WHEN CveCount>0 THEN 1 END) AS HostsWithCves,
                COUNT_BIG(CASE WHEN NmapCompleted=1 THEN 1 END) AS NmapCompleted,
                COUNT_BIG(CASE WHEN ShodanState=0 THEN 1 END) AS ShodanPending,
                COUNT_BIG(CASE WHEN ShodanState=2 THEN 1 END) AS ShodanRunning,
                COUNT_BIG(CASE WHEN ShodanState=3 THEN 1 END) AS ShodanFailed FROM #Inventory;
            SELECT TOP(6) Country AS Name, COUNT_BIG(*) AS Hosts FROM #Inventory
            WHERE Country IS NOT NULL GROUP BY Country ORDER BY Hosts DESC, Country;
            SELECT TOP(6) Organization AS Name, COUNT_BIG(*) AS Hosts FROM #Inventory
            WHERE Organization IS NOT NULL GROUP BY Organization ORDER BY Hosts DESC, Organization;
            SELECT * INTO #Matches FROM #Inventory i WHERE ({{predicate}}) AND
                (@Search=N'%%' OR i.IpAddress LIKE @Search OR i.Organization LIKE @Search
                OR i.Isp LIKE @Search OR i.Asn LIKE @Search OR i.Country LIKE @Search
                OR i.City LIKE @Search OR i.OperatingSystem LIKE @Search OR i.Domains LIKE @Search
                OR i.Cves LIKE @Search OR EXISTS (
                    SELECT 1 FROM dbo.Hostname n WHERE n.HostId=i.HostId AND n.Hostname LIKE @Search));
            DECLARE @Total bigint=(SELECT COUNT_BIG(*) FROM #Matches);
            DECLARE @LastPage int=CASE WHEN @Total=0 THEN 0 ELSE (@Total-1)/50 END;
            DECLARE @ActualPage int=CASE WHEN @Page>@LastPage THEN @LastPage ELSE @Page END;
            SELECT @Total AS Total, @ActualPage AS Page;
            SELECT HostId, IpAddress, Requests, LastSeen, PortCount, Organization, Isp, Asn, Country, City,
                OperatingSystem, CveCount, StatusCode, ShodanState, RetrievedAtUtc, ObservedAtUtc
            FROM #Matches ORDER BY {{order}}, HostId
            OFFSET (@ActualPage*50) ROWS FETCH NEXT 50 ROWS ONLY;
            """, new { Search = $"%{search}%", Page = page }, commandTimeout: 120, cancellationToken: cancellationToken));
        var summary = await results.ReadSingleAsync<CollectionSummary>();
        var countries = (await results.ReadAsync<CollectionFacet>()).ToArray();
        var organizations = (await results.ReadAsync<CollectionFacet>()).ToArray();
        var paging = await results.ReadSingleAsync<(long Total, int Page)>();
        var hosts = (await results.ReadAsync<IntelligenceHost>()).ToArray();
        return new(summary, countries, organizations, hosts, paging.Total, paging.Page, 50, DateTimeOffset.UtcNow);
    }

    public async Task<string?> EvidenceAsync(long hostId, long hostJobId, CancellationToken cancellationToken)
    {
        using var connection = new SqlConnection(_connectionString);
        return await connection.QuerySingleOrDefaultAsync<string>(new CommandDefinition("""
            SELECT e.ResponseJson FROM dbo.ReconEvidence e
            JOIN dbo.HostJob hj ON hj.HostJobId=e.HostJobId
            WHERE hj.HostId=@HostId AND e.HostJobId=@HostJobId;
            """, new { HostId = hostId, HostJobId = hostJobId }, cancellationToken: cancellationToken));
    }

    public async Task<RequestPage> RequestsAsync(long hostId, long? cursor, CancellationToken cancellationToken)
    {
        if (cursor is <= 0) throw new ArgumentException("Request cursor must be positive.");
        using var connection = new SqlConnection(_connectionString);
        var requests = (await connection.QueryAsync<CapturedRequest>(new CommandDefinition("""
            SELECT TOP(101) RequestId, Method, CONVERT(nvarchar(max),Target) AS Target,
                QueryString, TargetHost, CreatedDate FROM dbo.Request
            WHERE SourceHostId=@HostId AND (@Cursor IS NULL OR RequestId<@Cursor)
            ORDER BY RequestId DESC;
            """, new { HostId = hostId, Cursor = cursor }, cancellationToken: cancellationToken))).ToArray();
        return new(requests.Take(100).ToArray(), requests.Length > 100 ? requests[99].RequestId : null);
    }
}
