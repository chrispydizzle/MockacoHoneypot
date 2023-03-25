using Dapper;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SaltwaterTaffy;
using SaltwaterTaffy.Container;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Middlewares
{
    public class ReconTriggerMiddleware
    {
        private readonly RequestDelegate _next;

        public static List<Task> jobsRunning = new List<Task>();
        private const int maxJobs = 2;
        public static ConcurrentQueue<(string, string, long, long)> jobsToDo = new ConcurrentQueue<(string, string, long, long)>();

        public ReconTriggerMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(
            HttpContext httpContext,
            IMockacoContext mockacoContext,
            IOptionsSnapshot<MockacoOptions> statusCodeOptions,
            IMockProvider mockProvider,
            ILogger<ErrorHandlingMiddleware> logger)
        {
            try
            {
                lock (jobsRunning)
                {
                    while (jobsRunning.Count < maxJobs)
                    {
                        jobsRunning.Add(Task.Run(() => DoReconThing(logger)));
                    }
                }
                await _next(httpContext);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error doing the Recon thing. ");
            }
        }

        private async Task DoReconThing(ILogger<ErrorHandlingMiddleware> logger)
        {
            using var connection = new SqlConnection(@"Data Source=(LocalDB)\MSSQLLocalDB;AttachDbFilename=E:\Hacking\httpdb.mdf;Integrated Security=True;Connect Timeout=30");
            try
            {
                if (jobsToDo.IsEmpty)
                {
                    await this.TryLoadNewJobs(connection);
                    if (jobsToDo.IsEmpty)
                    {
                        //logger.LogInformation("No jobs!");
                        Thread.Sleep(10000);
                        return;
                    }
                }

                if (!jobsToDo.TryDequeue(out var f)) return;

                try
                {
                    logger.Log(LogLevel.Information, $"{f.Item1}:{f.Item2}");
                    var context = new NmapContext(ProcessWindowStyle.Hidden);
                    context.Options.Add(NmapFlag.TopPorts, "5000");
                    context.Options.Add(NmapFlag.TreatHostsAsOnline);
                    context.Options.Add(NmapFlag.ServiceVersion);
                    context.Options.Add(NmapFlag.HostTimeout, "10m");
                    context.Options.Add(NmapFlag.OsDetection);
                    context.Options.Add(NmapFlag.VersionAll);
                    context.Options.Add(NmapFlag.Verbose);
                    context.Target = f.Item1;
                    var r = context.Run();

                    ScanResult result = new ScanResult(r);
                    logger.Log(LogLevel.Information, "Detected {0} host(s), {1} up and {2} down.", result.Total, result.Up, result.Down);
                    foreach (Host i in result.Hosts)
                    {

                        var sqlInsert = @"INSERT INTO HostJob (JobId, HostId, State) VALUES (@JobId, @HostId, 1); SELECT @@IDENTITY";
                        var ident = connection.ExecuteScalar(sqlInsert, new { HostId = f.Item4, JobId = f.Item3 });
                        if (i.Hostnames.Any())
                        {
                            i.Hostnames.AsList().ForEach(hn =>
                            {
                                var sqlInsertHostname = @"INSERT INTO Hostname (HostId, Hostname) VALUES (@HostId, @HostName); SELECT @@IDENTITY";
                                var hnId = connection.ExecuteScalar(sqlInsertHostname, new { HostId = f.Item4, Hostname = hn });
                            });
                        }

                        foreach (Port j in i.Ports.Where(p => !p.Filtered))
                        {
                            var sqlInsertPort = @$"INSERT INTO Discovery (HostJobId, HostId, DiscoveryType, DiscoveryDetail, PortNumber) VALUES (@HostJobId, @HostId, 'Port', @DiscoveryDetail, @PortNumber); SELECT @@IDENTITY";
                            var identPort = connection.ExecuteScalar(sqlInsertPort, new { HostJobId = ident, HostId = f.Item4, DiscoveryDetail = $"{j.Service.Name ?? String.Empty} {j.Service.Version ?? String.Empty} {j.Service.Product ?? String.Empty} {j.Service.Os ?? String.Empty}", PortNumber = j.PortNumber });
                            logger.Log(LogLevel.Information, $"Port {j.PortNumber}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    logger.LogError(ex.Message, ex);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message, ex);
            }
            finally
            {
                // logger.Log(LogLevel.Information, $"Jobs running: {jobsRunning.Count} | Jobs in queue: {jobsToDo.Count}");
                jobsRunning.Remove(jobsRunning.First());
                if (jobsRunning.Count < maxJobs)
                {
                    jobsRunning.Add(Task.Run(() => DoReconThing(logger)));
                }
            }
        }

        private async Task TryLoadNewJobs(SqlConnection connection)
        {
            var sql = @"Select TOP 10 h.IpAddress, j.Name, j.JobId, h.HostId 
                    FROM Host h
                    JOIN (SELECT h.HostId, j.JobId 
		                    from dbo.Host h, dbo.Job j
		                    EXCEPT
		                    SELECT hj.HostId, hj.JobId from dbo.HostJob hj WHERE hj.State = 1) HostTodo on HostTodo.HostId = h.HostId
                    JOIN Job j on j.JobId = HostTodo.JobId";
            var newJobsToDo = await connection.QueryAsync<(string, string, long, long)>(sql, new { Count = 10 });
            newJobsToDo.Where(h => !string.IsNullOrEmpty(h.Item1)).AsList().ForEach(f => jobsToDo.Enqueue(f));
        }
    }
}
