using Mockaco.Recon;
using System;
using Xunit;

namespace Mockaco.Tests.Recon
{
    public class NmapScannerTest
    {
        [Fact]
        public void StoresOnlyOpenPortsAndServiceDetails()
        {
            var scan = NmapScanner.Parse(@"<!DOCTYPE nmaprun><nmaprun>
<host><status state='up'/><hostnames><hostname name='test'/><hostname name='test'/></hostnames>
<ports>
<port protocol='tcp' portid='80'><state state='open'/><service name='http' product='Test' version='1'/></port>
<port protocol='tcp' portid='81'><state state='closed'/></port>
<port protocol='tcp' portid='82'><state state='filtered'/></port>
<port protocol='tcp' portid='83'><state state='open|filtered'/></port>
</ports></host><runstats><finished exit='success'/></runstats></nmaprun>");
            Assert.Equal(new[] { "test" }, scan.Hostnames);
            Assert.Equal(new ReconPort(80, "tcp", "http 1 Test"), Assert.Single(scan.Ports));
        }

        [Theory]
        [InlineData("<nmaprun/>")]
        [InlineData("<nmaprun><host timedout='true'><status state='up'/></host><runstats><finished exit='success'/></runstats></nmaprun>")]
        [InlineData("<nmaprun><runstats><finished exit='error'/></runstats></nmaprun>")]
        public void RejectsIncompleteOrTimedOutScans(string xml)
        {
            Assert.Throws<InvalidOperationException>(() => NmapScanner.Parse(xml));
        }
    }
}
