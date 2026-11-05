namespace Mockaco.Analytics;

public sealed record CollectionSummary(long TotalHosts, long TotalRequests, long ServiceObservations,
    long ShodanAvailable, long ShodanNoData, long HostsWithCves, long NmapCompleted,
    long ShodanPending, long ShodanRunning, long ShodanFailed);
public sealed record CollectionFacet(string Name, long Hosts);
public sealed record IntelligenceHost(long HostId, string IpAddress, long Requests, DateTime? LastSeen,
    int PortCount, string? Organization, string? Isp, string? Asn, string? Country, string? City,
    string? OperatingSystem, int CveCount, int? StatusCode, short? ShodanState,
    DateTimeOffset? RetrievedAtUtc, string? ObservedAtUtc);
public sealed record IntelligenceCollection(CollectionSummary Summary, IReadOnlyList<CollectionFacet> Countries,
    IReadOnlyList<CollectionFacet> Organizations, IReadOnlyList<IntelligenceHost> Hosts,
    long Total, int Page, int PageSize, DateTimeOffset LoadedAt);
public sealed record RequestPage(IReadOnlyList<CapturedRequest> Requests, long? NextCursor);
public sealed record NonPublicHost(long HostId, string IpAddress, string Reason);
public sealed record HostPurgeCounts(long Hosts, long Requests, long Headers, long Jobs,
    long Discoveries, long Hostnames, long Evidence);
public sealed record HostCleanupPreview(IReadOnlyList<NonPublicHost> Hosts, HostPurgeCounts Counts);
public sealed record HostPurgeRequest(long[]? HostIds);
