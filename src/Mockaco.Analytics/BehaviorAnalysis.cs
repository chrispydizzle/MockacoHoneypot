using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Mockaco.Analytics;

public sealed class BehaviorAnalysis
{
    private readonly Dictionary<long, Dictionary<string, double>> _profiles = new();
    public AnalysisSnapshot Snapshot { get; private set; } = null!;

    internal void SetUnattributedRequests(long count) => Snapshot = Snapshot with { UnattributedRequests = count };

    public static BehaviorAnalysis Build(IEnumerable<RequestAggregate> requests,
        IEnumerable<ServiceObservation> observations, CancellationToken cancellationToken = default)
    {
        var analysis = new BehaviorAnalysis();
        var hosts = requests.Where(r => r.Count > 0).GroupBy(r => r.HostId).OrderBy(g => g.Key).ToArray();
        var counts = hosts.Select(host => host.GroupBy(r => $"{r.Method.ToUpperInvariant()} {NormalizePath(r.Target)}")
            .OrderBy(g => g.Key, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Sum(r => r.Count))).ToArray();
        var frequencies = counts.SelectMany(c => c.Keys).GroupBy(key => key)
            .ToDictionary(g => g.Key, g => g.Count());
        var vocabulary = frequencies.Keys.Order(StringComparer.Ordinal)
            .Select((key, index) => (key, index)).ToDictionary(item => item.key, item => item.index);
        var vectors = new KeyValuePair<int, double>[hosts.Length][];
        for (var i = 0; i < hosts.Length; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var weighted = counts[i].ToDictionary(pair => pair.Key,
                pair => (1 + Math.Log(pair.Value)) * (1 + Math.Log((hosts.Length + 1.0) / (frequencies[pair.Key] + 1))));
            var norm = Math.Sqrt(weighted.Values.Sum(value => value * value));
            var profile = weighted.ToDictionary(pair => pair.Key, pair => pair.Value / norm);
            analysis._profiles.Add(hosts[i].Key, profile);
            vectors[i] = profile.Select(pair => new KeyValuePair<int, double>(vocabulary[pair.Key], pair.Value)).ToArray();
        }

        var (coordinates, variance) = Project(vectors, vocabulary.Count, cancellationToken);
        var services = observations.Where(o => o.DiscoveryType.Equals("Port", StringComparison.OrdinalIgnoreCase))
            .GroupBy(o => o.HostId).ToDictionary(g => g.Key,
                g => g.Select(ServiceName).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray());
        var sources = hosts.Select((host, i) =>
        {
            var families = host.GroupBy(r => ClassifyPath(r.Target))
                .ToDictionary(g => g.Key, g => g.Sum(r => r.Count));
            var keys = counts[i].Keys.ToArray();
            var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(keys))));
            var label = string.Join(" + ", keys.Take(2)) + (keys.Length > 2 ? $" + {keys.Length - 2} more" : "");
            return new SourcePoint(host.Key, host.First().IpAddress, host.Sum(r => r.Count),
                host.Min(r => r.FirstSeen), host.Max(r => r.LastSeen),
                families.OrderByDescending(f => f.Value).ThenBy(f => f.Key, StringComparer.Ordinal).First().Key,
                families.Keys.Order(StringComparer.Ordinal).ToArray(),
                services.GetValueOrDefault(host.Key) ?? Array.Empty<string>(), keys.Length, fingerprint, label,
                coordinates[i][0], coordinates[i][1]);
        }).ToArray();
        analysis.Snapshot = new(sources, sources.Sum(s => s.Requests),
            sources.Length == 0 ? null : sources.Min(s => s.FirstSeen),
            sources.Length == 0 ? null : sources.Max(s => s.LastSeen), variance, DateTimeOffset.UtcNow);
        return analysis;
    }

    public static string NormalizePath(string target)
    {
        if (string.IsNullOrEmpty(target)) return "(empty target)";
        var path = target.Split('?', 2)[0];
        try { path = Uri.UnescapeDataString(path); }
        catch (UriFormatException) { }
        return string.Join("/", path.Split('/').Select(segment =>
            (segment.Length > 0 && segment.All(char.IsAsciiDigit)) || Guid.TryParse(segment, out _)
                ? "{id}" : segment));
    }

    public static string ClassifyPath(string target)
    {
        var path = NormalizePath(target).ToLowerInvariant();
        if (path == "(empty target)") return "Empty target";
        if (Regex.IsMatch(path, @"(^|/)(\.env[^/]*|\.git|\.aws|\.svn|credentials)(/|$)") ||
            path.Contains("config.") || path.EndsWith(".sql") || path.EndsWith(".bak"))
            return "Secrets & config";
        if (path.Contains("wp-") || path.Contains("wordpress") || path.EndsWith("/xmlrpc.php"))
            return "WordPress";
        if (path.Contains("cgi-sys") || path.Contains("cpanel") || path.Contains("plesk") ||
            Regex.IsMatch(path, @"(^|/)(admin|administrator|webadmin|phpmyadmin|whm)([/.]|$)"))
            return "Control panels";
        if (path.Contains("login") || path.Contains("logon") || path.Contains("signin") ||
            path.Contains("captcha") || Regex.IsMatch(path, @"(^|/)auth([/.]|$)"))
            return "Authentication";
        if (path.Contains("boaform") || path.Contains("goform") || path.Contains("hnap") || path.Contains("gpon"))
            return "Device interfaces";
        if (Regex.IsMatch(path, @"(^|/)(api|graphql|actuator|solr|jenkins)([/.]|$)"))
            return "APIs & applications";
        if (path.EndsWith(".php")) return "PHP endpoints";
        if (path is "/" or "/favicon.ico" or "/robots.txt" or "/sitemap.xml")
            return "Site discovery";
        return "Other paths";
    }

    private static string ServiceName(ServiceObservation observation)
    {
        var parts = observation.Detail.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        var offset = parts.Length > 0 && parts[0] is "tcp" or "udp" or "sctp" ? 1 : 0;
        return parts.Length > offset ? parts[offset].ToLowerInvariant()
            : $"unidentified:{observation.PortNumber?.ToString() ?? "port not recorded"}";
    }

    public IReadOnlyList<SimilarSource> Neighbors(long hostId, int count)
    {
        if (count < 1) throw new ArgumentException("Neighbor count must be positive.");
        if (!_profiles.TryGetValue(hostId, out var selected)) return Array.Empty<SimilarSource>();
        var matches = _profiles.Where(pair => pair.Key != hostId)
            .Select(pair => (pair.Key, Profile: pair.Value,
                Score: selected.Sum(feature => feature.Value * pair.Value.GetValueOrDefault(feature.Key))))
            .Where(match => match.Score > 1e-9).OrderByDescending(match => match.Score).ThenBy(match => match.Key)
            .Take(count);
        var addresses = Snapshot.Sources.ToDictionary(source => source.HostId, source => source.IpAddress);
        return matches.Select(match => new SimilarSource(match.Key, addresses[match.Key], Math.Clamp(match.Score, 0, 1),
            selected.Keys.Intersect(match.Profile.Keys).Order(StringComparer.Ordinal).ToArray())).ToArray();
    }

    // Sparse, centered PCA: work scales with observed host/path pairs, not all pairs of hosts.
    private static (double[][] Coordinates, double Variance) Project(
        KeyValuePair<int, double>[][] vectors, int dimensions, CancellationToken cancellationToken)
    {
        var coordinates = vectors.Select(_ => new double[2]).ToArray();
        if (vectors.Length < 2 || dimensions == 0) return (coordinates, 0);
        var mean = new double[dimensions];
        foreach (var vector in vectors)
            foreach (var entry in vector) mean[entry.Key] += entry.Value / vectors.Length;
        var totalVariance = vectors.Length * (1 - mean.Sum(value => value * value));
        if (totalVariance < 1e-10) return (coordinates, 0);
        var axes = new List<double[]>();
        var retained = 0.0;
        for (var component = 0; component < 2; component++)
        {
            var axis = Enumerable.Range(0, dimensions).Select(i => Math.Sin((i + 1) * (component + 1.618))).ToArray();
            for (var iteration = 0; iteration < 48; iteration++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var next = new double[dimensions];
                var offset = Dot(axis, mean);
                var sum = 0.0;
                foreach (var vector in vectors)
                {
                    var score = vector.Sum(entry => entry.Value * axis[entry.Key]) - offset;
                    sum += score;
                    foreach (var entry in vector) next[entry.Key] += entry.Value * score;
                }
                for (var j = 0; j < dimensions; j++) next[j] -= mean[j] * sum;
                foreach (var previous in axes)
                {
                    var overlap = Dot(next, previous);
                    for (var j = 0; j < dimensions; j++) next[j] -= overlap * previous[j];
                }
                var length = Math.Sqrt(Dot(next, next));
                if (length < 1e-12) { axis = new double[dimensions]; break; }
                for (var j = 0; j < dimensions; j++) next[j] /= length;
                axis = next;
            }
            axes.Add(axis);
            var meanScore = Dot(axis, mean);
            for (var i = 0; i < vectors.Length; i++)
            {
                var score = vectors[i].Sum(entry => entry.Value * axis[entry.Key]) - meanScore;
                coordinates[i][component] = score;
                retained += score * score;
            }
        }
        return (coordinates, Math.Clamp(retained / totalVariance, 0, 1));
    }

    private static double Dot(double[] left, double[] right)
    {
        var sum = 0.0;
        for (var i = 0; i < left.Length; i++) sum += left[i] * right[i];
        return sum;
    }
}
