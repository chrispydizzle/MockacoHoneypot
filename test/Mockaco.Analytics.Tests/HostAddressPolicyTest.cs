using Mockaco.Analytics;
using Xunit;

namespace Mockaco.Analytics.Tests;

public class HostAddressPolicyTest
{
    [Theory]
    [InlineData("192.168.1.56")]
    [InlineData("10.0.0.1")]
    [InlineData("172.16.0.0")]
    [InlineData("172.31.255.255")]
    [InlineData("100.64.0.0")]
    [InlineData("100.127.255.255")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.10.1")]
    [InlineData("0.0.0.0")]
    [InlineData("192.0.0.8")]
    [InlineData("192.0.0.11")]
    [InlineData("192.0.2.1")]
    [InlineData("198.51.100.1")]
    [InlineData("203.0.113.1")]
    [InlineData("198.18.0.0")]
    [InlineData("198.19.255.255")]
    [InlineData("224.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("::ffff:192.168.1.56")]
    [InlineData("fc00::1")]
    [InlineData("fdff::1")]
    [InlineData("fe80::1%2")]
    [InlineData("fec0::1")]
    [InlineData("ff02::1")]
    [InlineData("64:ff9b:1::1")]
    [InlineData("100::1")]
    [InlineData("100:0:0:1::1")]
    [InlineData("2001:2::1")]
    [InlineData("2001:db8::1")]
    [InlineData("3fff::1")]
    [InlineData("5f00::1")]
    [InlineData("not-an-address")]
    [InlineData("192.168.1.999")]
    [InlineData("")]
    public void Non_public_or_malformed_hosts_have_a_cleanup_reason(string address)
    {
        Assert.False(string.IsNullOrEmpty(HostAddressPolicy.NonPublicReason(address)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("8.8.8.0")]
    [InlineData("172.15.255.255")]
    [InlineData("172.32.0.0")]
    [InlineData("100.63.255.255")]
    [InlineData("100.128.0.0")]
    [InlineData("198.17.255.255")]
    [InlineData("198.20.0.0")]
    [InlineData("192.0.0.9")]
    [InlineData("192.0.0.10")]
    [InlineData("192.31.196.1")]
    [InlineData("::ffff:8.8.8.8")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("64:ff9b::808:808")]
    [InlineData("2001:1::1")]
    [InlineData("2001:1::2")]
    [InlineData("2001:1::3")]
    [InlineData("2001:3::1")]
    [InlineData("2001:4:112::1")]
    [InlineData("2001:20::1")]
    [InlineData("2001:30::1")]
    [InlineData("2001:0:4136:e378:8000:63bf:3fff:fdd2")]
    [InlineData("2002:0808:0808::1")]
    public void Public_and_conditionally_routable_hosts_are_not_purge_candidates(string address)
    {
        Assert.Null(HostAddressPolicy.NonPublicReason(address));
    }
}
