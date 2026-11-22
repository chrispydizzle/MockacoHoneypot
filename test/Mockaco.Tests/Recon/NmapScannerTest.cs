using Mockaco.Recon;
using System;
using System.Text.Json;
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
        [InlineData("<nmaprun><runstats><finished exit='success'/></runstats></nmaprun>")]
        [InlineData("<nmaprun><host timedout='true'><status state='up'/></host><runstats><finished exit='success'/></runstats></nmaprun>")]
        [InlineData("<nmaprun><runstats><finished exit='error'/></runstats></nmaprun>")]
        public void RejectsIncompleteOrTimedOutScans(string xml)
        {
            Assert.Throws<InvalidOperationException>(() => NmapScanner.Parse(xml));
        }

        [Fact]
        public void PreservesFullXmlIncludingHttpScriptsOsAndNonOpenPorts()
        {
            var xml = @"<?xml version='1.0'?>
<!DOCTYPE nmaprun><nmaprun args='nmap --script default,http-enum,http-headers'>
<prescript><script id='pre' output='pre-scan output'/></prescript>
<host><status state='up'/><hostnames/><ports>
<port protocol='tcp' portid='443'><state state='open'/>
<service name='https' product='Example' tunnel='ssl'><cpe>cpe:/a:example</cpe></service>
<script id='http-enum' output='/admin/: Admin portal&#10;/api/: API'>
<table key='endpoints'><elem key='path'>/admin/?a=1&amp;b=2</elem></table></script>
<script id='http-title' output='Portal &#x96EA;'/>
<script id='http-headers' output='Server: example&#10;X-Detail: retained'/>
</port><port protocol='tcp' portid='444'><state state='filtered' reason='no-response'/></port>
</ports><os><osmatch name='Example OS' accuracy='98'/></os>
<hostscript><script id='host-info' output='host data'/></hostscript>
<trace><hop ttl='1' ipaddr='192.0.2.1'/></trace></host>
<postscript><script id='post' output='post-scan output'/></postscript>
<runstats><finished exit='success' elapsed='12.5'/></runstats></nmaprun>";
            var warning = "Warning: OS detection unreliable.\r\n" + new string('x', 5000) + "\u96ea";
            var scan = NmapScanner.Parse(xml, warning);
            var output = JsonSerializer.Deserialize<NmapOutput>(scan.Evidence.ResponseJson);
            Assert.Equal(xml, output.Xml);
            Assert.Equal(warning, output.StandardError);
            Assert.Equal(0, output.ExitCode);
            Assert.Null(scan.Evidence.StatusCode);
            Assert.Equal(DateTimeKind.Utc, scan.Evidence.RetrievedAtUtc.Kind);
            Assert.Equal(443, Assert.Single(scan.Ports).Number);
        }
    }
}
