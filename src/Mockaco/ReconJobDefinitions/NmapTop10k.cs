namespace Mockaco.ReconJobDefinitions
{
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public class NmapTop10k : IJob
    {
        public List<Discovery> Discoveries => throw new System.NotImplementedException();

        public Task Execute()
        {
            throw new System.NotImplementedException();
        }
    }

    public enum JobName
    {
        NmapTop10k
    }

    public interface IJob
    {
        Task Execute();
        public List<Discovery> Discoveries { get; }
    }

    public class Discovery
    {
        public Host Host { get; set; }
        public string DiscoveryType { get; set; }
        public string DiscoveryDetail { get; set; }
    }

    public class HostJob
    {
        public long HostJobId { get; set; }
        public Job Job { get; set; }
        public Host Host { get; set; }
    }

    public class Host
    {
        public long HostId { get; set; }
        public string IpAddress { get; set; }
    }

    public class Job
    {
        public long JobId { get; set; }
        public string Name { get; set; }
    }

}
