namespace Mockaco
{
    public sealed class HoneypotOptions
    {
        public string ProfilesPath { get; set; } = "Profiles";
        public string ConnectionString { get; set; } =
            "Data Source=localhost;Initial Catalog=HttpDb;Integrated Security=True;Connect Timeout=30;Encrypt=False;";
        public int DefaultStatusCode { get; set; } = 200;
        public int UnmatchedStatusCode { get; set; } = 501;
        public string DefaultContentType { get; set; } = "application/json";
    }
}
