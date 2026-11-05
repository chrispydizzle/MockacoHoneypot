namespace Mockaco.Recon
{
    public sealed class ReconOptions
    {
        public int Workers { get; set; } = 8;
        public int PollIntervalSeconds { get; set; } = 2;
        public string Executable { get; set; } = "nmap";
        public int TopPorts { get; set; } = 5000;
        public string Ports { get; set; }
        public string HostTimeout { get; set; } = "10m";
        public int ProcessTimeoutSeconds { get; set; } = 660;
        public bool DetectOperatingSystem { get; set; } = true;
        public bool ExhaustiveVersionDetection { get; set; } = true;
        public string ConnectionString { get; set; } =
            "Data Source=localhost;Initial Catalog=HttpDb;Integrated Security=True;Connect Timeout=30;TrustServerCertificate=True;";
    }
}
