using Mockaco.Analytics;
using Xunit;

namespace Mockaco.Analytics.Tests;

public class BehaviorAnalysisTest
{
    private static readonly DateTime Seen = new(2023, 6, 1, 12, 0, 0);

    [Theory]
    [InlineData("/users/123", "/users/{id}", "Other paths")]
    [InlineData("/users/456?token=abc", "/users/{id}", "Other paths")]
    [InlineData("/api/items/4f5dd64f-971f-40fa-a377-14caa3f8690d", "/api/items/{id}", "APIs & applications")]
    [InlineData("/%77p-login.php", "/wp-login.php", "WordPress")]
    [InlineData("/.env", "/.env", "Secrets & config")]
    [InlineData("/cgi-sys/defaultwebpage.cgi", "/cgi-sys/defaultwebpage.cgi", "Control panels")]
    [InlineData("/captcha", "/captcha", "Authentication")]
    [InlineData("/Q.php", "/Q.php", "PHP endpoints")]
    [InlineData("", "(empty target)", "Empty target")]
    [InlineData("/", "/", "Site discovery")]
    public void Normalization_keeps_meaningful_paths_and_merges_only_id_segments(
        string target, string normalized, string family)
    {
        Assert.Equal(normalized, BehaviorAnalysis.NormalizePath(target));
        Assert.Equal(family, BehaviorAnalysis.ClassifyPath(target));
    }

    [Fact]
    public void Similarity_uses_behavior_not_request_volume_or_service_exposure()
    {
        var analysis = BehaviorAnalysis.Build(new[]
        {
            Request(1, "/wp-login.php", 100), Request(1, "/xmlrpc.php", 100),
            Request(2, "/wp-login.php", 1), Request(2, "/xmlrpc.php", 1),
            Request(3, "/admin", 100),
            Request(4, "/wp-login.php", 100, "POST")
        }, new[] { new ServiceObservation(3, 22, "ssh OpenSSH", "Port") });

        var match = Assert.Single(analysis.Neighbors(1, 10));
        Assert.Equal(2, match.HostId);
        Assert.Equal(1, match.Similarity, 10);
        Assert.Equal(new[] { "GET /wp-login.php", "GET /xmlrpc.php" }, match.SharedPaths);
        var first = analysis.Snapshot.Sources.Single(s => s.HostId == 1);
        var second = analysis.Snapshot.Sources.Single(s => s.HostId == 2);
        Assert.Equal(first.Fingerprint, second.Fingerprint);
        Assert.Equal(first.X, second.X, 10);
        Assert.Equal(first.Y, second.Y, 10);
        Assert.Equal(402, analysis.Snapshot.RequestCount);
    }

    [Fact]
    public void Services_deduplicate_per_source_and_handle_legacy_and_current_banners()
    {
        var analysis = BehaviorAnalysis.Build(new[] { Request(1, "/"), Request(2, "/") }, new[]
        {
            new ServiceObservation(1, 22, "ssh 7.4 OpenSSH", "Port"),
            new ServiceObservation(1, 2222, "tcp ssh 9.0 OpenSSH", "Port"),
            new ServiceObservation(1, 80, "tcp tcpwrapped", "Port"),
            new ServiceObservation(1, 443, "   ", "Port"),
            new ServiceObservation(2, null, "example.test", "Hostname"),
            new ServiceObservation(99, 21, "ftp", "Port")
        });

        Assert.Equal(new[] { "ssh", "tcpwrapped", "unidentified:443" },
            analysis.Snapshot.Sources.Single(s => s.HostId == 1).Services);
        Assert.Empty(analysis.Snapshot.Sources.Single(s => s.HostId == 2).Services);
        Assert.Equal(2, analysis.Snapshot.Sources.Count);
    }

    [Fact]
    public void Projection_is_finite_for_empty_or_identical_profiles_and_stable_under_input_reordering()
    {
        var empty = BehaviorAnalysis.Build(Array.Empty<RequestAggregate>(), Array.Empty<ServiceObservation>());
        Assert.Empty(empty.Snapshot.Sources);
        Assert.Equal(0, empty.Snapshot.ExplainedVariance);

        var requests = new[]
        {
            Request(3, "/api/items/123"), Request(1, "/api/items/456"), Request(2, "/api/items/789")
        };
        var first = BehaviorAnalysis.Build(requests, Array.Empty<ServiceObservation>());
        var reversed = BehaviorAnalysis.Build(requests.Reverse(), Array.Empty<ServiceObservation>());
        Assert.Equal(first.Snapshot.Sources.Select(s => (s.HostId, s.X, s.Y, s.Fingerprint)),
            reversed.Snapshot.Sources.Select(s => (s.HostId, s.X, s.Y, s.Fingerprint)));
        Assert.All(first.Snapshot.Sources, source =>
        {
            Assert.True(double.IsFinite(source.X));
            Assert.True(double.IsFinite(source.Y));
        });
        Assert.Equal(0, first.Snapshot.ExplainedVariance);
        Assert.Equal(2, first.Neighbors(1, 10).Count);
    }

    [Fact]
    public void Cohorts_include_every_requested_family_not_only_the_dominant_one()
    {
        var analysis = BehaviorAnalysis.Build(new[]
        {
            Request(1, "/admin", 50), Request(1, "/wp-login.php"), Request(1, "/xmlrpc.php"),
            Request(2, "/Q.php", 5)
        }, Array.Empty<ServiceObservation>());

        var source = analysis.Snapshot.Sources.Single(s => s.HostId == 1);
        Assert.Equal("Control panels", source.DominantFamily);
        Assert.Equal(new[] { "Control panels", "WordPress" }, source.Families);
        Assert.Equal(3, source.PathCount);
        Assert.Equal(57, analysis.Snapshot.RequestCount);
        Assert.InRange(analysis.Snapshot.ExplainedVariance, 0, 1);
    }

    [Theory]
    [InlineData("not-a-date", null)]
    [InlineData("2023-02-30", null)]
    [InlineData("2023-06-01", "2023-06-01")]
    [InlineData("2023-06-02", "2023-06-01")]
    public void Invalid_or_empty_date_windows_are_rejected(string from, string? before)
    {
        Assert.Throws<ArgumentException>(() => AnalysisWindow.Parse(from, before));
    }

    [Fact]
    public void Date_window_uses_database_clock_and_an_exclusive_end()
    {
        var window = AnalysisWindow.Parse("2023-06-01", "2023-06-02");
        Assert.Equal(new DateTime(2023, 6, 1), window.From);
        Assert.Equal(new DateTime(2023, 6, 2), window.Before);
        Assert.Equal(DateTimeKind.Unspecified, window.From!.Value.Kind);
        Assert.Equal(new AnalysisWindow(null, null), AnalysisWindow.Parse(null, null));
    }

    private static RequestAggregate Request(long id, string target, long count = 1, string method = "GET") =>
        new(id, $"192.0.2.{id}", method, target, count, Seen, Seen);
}
