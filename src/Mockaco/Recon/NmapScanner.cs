using Microsoft.Extensions.Options;
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace Mockaco.Recon
{
    public sealed class NmapScanner : INmapScanner
    {
        private readonly ReconOptions _options;

        public NmapScanner(IOptions<ReconOptions> options) => _options = options.Value;

        public async Task<ReconScan> ScanAsync(string target, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var address = IPAddress.Parse(target);
            var start = new ProcessStartInfo(_options.Executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            start.ArgumentList.Add(string.IsNullOrWhiteSpace(_options.Ports) ? "--top-ports" : "-p");
            start.ArgumentList.Add(string.IsNullOrWhiteSpace(_options.Ports)
                ? _options.TopPorts.ToString(CultureInfo.InvariantCulture) : _options.Ports);
            foreach (var argument in new[] { "-Pn", "-sV", "--host-timeout", _options.HostTimeout, "-v", "-oX", "-" })
                start.ArgumentList.Add(argument);
            if (_options.DetectOperatingSystem) start.ArgumentList.Add("-O");
            if (_options.ExhaustiveVersionDetection) start.ArgumentList.Add("--version-all");
            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                start.ArgumentList.Add("-6");
            start.ArgumentList.Add(address.ToString());

            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(_options.ProcessTimeoutSeconds));
            using var process = new Process { StartInfo = start };
            process.Start();
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            try
            {
                await process.WaitForExitAsync(deadline.Token);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException) when (process.HasExited) { }
                await process.WaitForExitAsync(CancellationToken.None);
                await Task.WhenAll(output, error);
                cancellationToken.ThrowIfCancellationRequested();
                throw new TimeoutException($"Nmap exceeded {_options.ProcessTimeoutSeconds}s for {target}.");
            }
            await Task.WhenAll(output, error);
            if (process.ExitCode != 0)
                throw new InvalidOperationException($"Nmap exited {process.ExitCode} for {target}: {error.Result}");
            return Parse(output.Result);
        }

        public static ReconScan Parse(string xml)
        {
            using var reader = XmlReader.Create(new StringReader(xml),
                new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null });
            var document = XDocument.Load(reader);
            var finish = document.Root?.Element("runstats")?.Element("finished");
            if (finish == null || (string)finish.Attribute("exit") != "success")
                throw new InvalidOperationException("Nmap output is incomplete or reports failure.");
            var hosts = document.Root.Elements("host").ToArray();
            if (hosts.Length != 1 || (string)hosts[0].Attribute("timedout") == "true"
                || (string)hosts[0].Element("status")?.Attribute("state") != "up") 
                Trace.WriteLine("Nmap did not complete a scan of the requested host within the time limit.");
            var host = hosts[0];
            var names = host.Element("hostnames")?.Elements("hostname")
                .Select(name => (string)name.Attribute("name"))
                .Where(name => !string.IsNullOrEmpty(name)).Distinct().ToArray() ?? Array.Empty<string>();
            var ports = host.Element("ports")?.Elements("port")
                .Where(port => (string)port.Element("state")?.Attribute("state") == "open")
                .Select(port => new ReconPort(
                    int.Parse((string)port.Attribute("portid"), CultureInfo.InvariantCulture),
                    (string)port.Attribute("protocol"),
                    string.Join(" ", new[] { "name", "version", "product", "ostype" }
                        .Select(attribute => (string)port.Element("service")?.Attribute(attribute))
                        .Where(value => !string.IsNullOrEmpty(value)))))
                .ToArray() ?? Array.Empty<ReconPort>();
            return new ReconScan(names, ports);
        }
    }
}
