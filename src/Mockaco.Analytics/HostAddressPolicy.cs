using System.Net;
using System.Net.Sockets;

namespace Mockaco.Analytics;

public static class HostAddressPolicy
{
    // IANA special-purpose registries, 2025-10-09. Preserve global and conditional exceptions.
    private static readonly IPNetwork[] PublicExceptions = new[]
    {
        "192.0.0.9/32", "192.0.0.10/32", "64:ff9b::/96", "2001::/32",
        "2001:1::1/128", "2001:1::2/128", "2001:1::3/128", "2001:3::/32",
        "2001:4:112::/48", "2001:20::/28", "2001:30::/28"
    }.Select(IPNetwork.Parse).ToArray();
    private static readonly (IPNetwork Network, string Reason)[] NonPublicRanges = new (string Prefix, string Reason)[]
    {
        ("0.0.0.0/8", "Unspecified / this network"),
        ("10.0.0.0/8", "Private-use"),
        ("100.64.0.0/10", "Shared address space"),
        ("127.0.0.0/8", "Loopback"),
        ("169.254.0.0/16", "Link-local"),
        ("172.16.0.0/12", "Private-use"),
        ("192.0.0.0/24", "Reserved protocol assignment"),
        ("192.0.2.0/24", "Documentation"),
        ("192.88.99.0/24", "Deprecated relay assignment"),
        ("192.168.0.0/16", "Private-use"),
        ("198.18.0.0/15", "Benchmark"),
        ("198.51.100.0/24", "Documentation"),
        ("203.0.113.0/24", "Documentation"),
        ("224.0.0.0/4", "Multicast"),
        ("240.0.0.0/4", "Reserved / broadcast"),
        ("::/128", "Unspecified"),
        ("::1/128", "Loopback"),
        ("64:ff9b:1::/48", "Local translation"),
        ("100::/64", "Discard-only"),
        ("100:0:0:1::/64", "Dummy address"),
        ("2001:2::/48", "Benchmark"),
        ("2001::/23", "Reserved protocol assignment"),
        ("2001:db8::/32", "Documentation"),
        ("3fff::/20", "Documentation"),
        ("5f00::/16", "Segment-routing local scope"),
        ("fc00::/7", "Unique-local"),
        ("fe80::/10", "Link-local"),
        ("fec0::/10", "Deprecated site-local"),
        ("ff00::/8", "Multicast")
    }.Select(item => (IPNetwork.Parse(item.Prefix), item.Reason)).ToArray();
    private static readonly IPNetwork GlobalUnicastV6 = IPNetwork.Parse("2000::/3");

    public static string? NonPublicReason(string? value)
    {
        if (!IPAddress.TryParse(value, out var address)) return "Malformed address";
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (PublicExceptions.Any(network => network.Contains(address))) return null;
        foreach (var (network, reason) in NonPublicRanges)
            if (network.Contains(address)) return reason;
        return address.AddressFamily == AddressFamily.InterNetworkV6 && !GlobalUnicastV6.Contains(address)
            ? "Reserved IPv6 space" : null;
    }
}
