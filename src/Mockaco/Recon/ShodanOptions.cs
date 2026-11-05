namespace Mockaco.Recon
{
    public sealed class ShodanOptions
    {
        public string ApiKey { get; set; }
        public string ConnectionString { get; set; }
        public double RequestIntervalSeconds { get; set; } = 1;
        public int RequestTimeoutSeconds { get; set; } = 30;
        public double PollIntervalSeconds { get; set; } = 2;
        public double RetryDelaySeconds { get; set; } = 15;
        public double MaxRetryDelaySeconds { get; set; } = 300;
    }
}
