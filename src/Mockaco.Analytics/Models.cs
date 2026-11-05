using System.Globalization;

namespace Mockaco.Analytics;

public sealed record RequestAggregate(long HostId, string IpAddress, string Method, string Target,
    long Count, DateTime FirstSeen, DateTime LastSeen);

public sealed record ServiceObservation(long HostId, int? PortNumber, string Detail, string DiscoveryType);

public sealed record SourcePoint(long HostId, string IpAddress, long Requests, DateTime FirstSeen,
    DateTime LastSeen, string DominantFamily, string[] Families, string[] Services, int PathCount,
    string Fingerprint, string FingerprintLabel, double X, double Y);

public sealed record AnalysisSnapshot(IReadOnlyList<SourcePoint> Sources, long RequestCount,
    DateTime? FirstSeen, DateTime? LastSeen, double ExplainedVariance, DateTimeOffset LoadedAt,
    long UnattributedRequests = 0);

public sealed record SimilarSource(long HostId, string IpAddress, double Similarity, string[] SharedPaths);

public sealed record AnalysisWindow(DateTime? From, DateTime? Before)
{
    public static AnalysisWindow Parse(string? from, string? before)
    {
        var start = ParseDate(from);
        var end = ParseDate(before);
        if (start.HasValue && end.HasValue && start >= end)
            throw new ArgumentException("From must be earlier than Before. Before is exclusive.");
        return new(start, end);
    }

    private static DateTime? ParseDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (!DateTime.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture,
            DateTimeStyles.None, out var date) || date.Year < 1753)
            throw new ArgumentException("Use dates in YYYY-MM-DD format, in 1753 or later.");
        return date;
    }
}

public sealed record CapturedRequest(long RequestId, string Method, string Target, string? QueryString,
    string? TargetHost, DateTime CreatedDate);
public sealed record CapturedService(int? PortNumber, string Detail, long HostJobId, DateTime JobUpdatedAt,
    string Provider, DateTimeOffset? ObservedAtUtc, DateTimeOffset? RetrievedAtUtc);
public sealed record ReconState(long HostJobId, short State, DateTime UpdatedAt, string? LastError,
    string Provider, int? StatusCode, DateTimeOffset? RetrievedAtUtc);
public sealed record SourceDetail(long HostId, string IpAddress, IReadOnlyList<string> Hostnames,
    IReadOnlyList<CapturedService> Services, IReadOnlyList<ReconState> Jobs,
    IReadOnlyList<RequestAggregate> Paths, IReadOnlyList<CapturedRequest> Requests, long? NextCursor);
