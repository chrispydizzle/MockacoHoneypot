using Dapper;
using Microsoft.Extensions.Options;
using System;
using System.Data.SqlClient;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Recon
{
    public sealed class SqlReconJobStore : IReconJobStore
    {
        private readonly ReconOptions _options;
        private readonly string _provider;
        public SqlReconJobStore(IOptions<ReconOptions> options, string provider = "Nmap")
        {
            _options = options.Value;
            _provider = provider;
        }

        public async Task<ReconJob> ClaimAsync(CancellationToken cancellationToken)
        {
            using var connection = new SqlConnection(_options.ConnectionString);
            await connection.OpenAsync(cancellationToken);
            using var transaction = connection.BeginTransaction();
            // Serialize only job selection; scans and result writes remain concurrent.
            const string sql = @"
DECLARE @LockResult int;
EXEC @LockResult = sys.sp_getapplock @Resource = 'Mockaco.Recon.Claim',
    @LockMode = 'Exclusive', @LockOwner = 'Transaction', @LockTimeout = 10000;
IF @LockResult < 0 THROW 50001, 'Could not acquire recon claim lock', 1;
IF @Provider = 'Shodan' AND NOT EXISTS (SELECT 1 FROM dbo.Job WHERE Provider = @Provider)
    INSERT dbo.Job (Name, Provider) VALUES ('ShodanHostLookup', @Provider);
DECLARE @Id bigint;
SELECT TOP (1) @Id = hj.HostJobId FROM dbo.HostJob hj WITH (UPDLOCK)
JOIN dbo.Job j ON j.JobId = hj.JobId
WHERE j.Provider = @Provider AND (hj.State = 0 OR (hj.State = 2 AND hj.LeaseUntil < SYSUTCDATETIME()))
ORDER BY hj.HostJobId;
IF @Id IS NULL
BEGIN
    INSERT INTO dbo.HostJob (HostId, JobId, State)
    SELECT TOP (1) h.HostId, j.JobId, 0 FROM dbo.Host h CROSS JOIN dbo.Job j
    WHERE j.Provider = @Provider
        AND NOT EXISTS (SELECT 1 FROM dbo.HostJob hj WHERE hj.HostId = h.HostId AND hj.JobId = j.JobId)
    ORDER BY h.HostId, j.JobId;
    IF @@ROWCOUNT > 0 SET @Id = SCOPE_IDENTITY();
END;
UPDATE dbo.HostJob SET State = 2, LeaseToken = @Token,
    LeaseUntil = DATEADD(second, @LeaseSeconds, SYSUTCDATETIME()),
    UpdatedAt = GETDATE(), LastError = NULL
WHERE HostJobId = @Id;
SELECT hj.HostJobId, hj.HostId, h.IpAddress AS Target, hj.LeaseToken
FROM dbo.HostJob hj JOIN dbo.Host h ON h.HostId = hj.HostId WHERE hj.HostJobId = @Id;";
            var job = await connection.QuerySingleOrDefaultAsync<ReconJob>(new CommandDefinition(sql,
                new { Token = Guid.NewGuid(), LeaseSeconds = checked(_options.ProcessTimeoutSeconds + 120), Provider = _provider },
                transaction, cancellationToken: cancellationToken));
            transaction.Commit();
            return job;
        }

        public async Task CompleteAsync(ReconJob job, ReconScan scan, CancellationToken cancellationToken)
        {
            using var connection = new SqlConnection(_options.ConnectionString);
            await connection.OpenAsync(cancellationToken);
            using var transaction = connection.BeginTransaction();
            var owned = await connection.ExecuteScalarAsync<int>(new CommandDefinition(@"
SELECT COUNT(*) FROM dbo.HostJob WITH (UPDLOCK, HOLDLOCK)
WHERE HostJobId = @HostJobId AND State = 2 AND LeaseToken = @LeaseToken
AND LeaseUntil > SYSUTCDATETIME();", job, transaction, cancellationToken: cancellationToken));
            if (owned != 1) throw new InvalidOperationException($"Recon job {job.HostJobId} lease was lost.");
            if (scan.Evidence != null)
                await connection.ExecuteAsync(new CommandDefinition(@"
INSERT dbo.ReconEvidence (HostJobId, StatusCode, RetrievedAtUtc, ResponseJson)
VALUES (@HostJobId, @StatusCode, @RetrievedAtUtc, @ResponseJson);",
                    new { job.HostJobId, scan.Evidence.StatusCode, scan.Evidence.RetrievedAtUtc, scan.Evidence.ResponseJson },
                    transaction, cancellationToken: cancellationToken));
            foreach (var name in scan.Hostnames)
                await connection.ExecuteAsync(new CommandDefinition(@"
INSERT INTO dbo.Hostname (HostId, Hostname)
SELECT @HostId, @Name WHERE NOT EXISTS
(SELECT 1 FROM dbo.Hostname WHERE HostId = @HostId AND Hostname = @Name);",
                    new { job.HostId, Name = name }, transaction, cancellationToken: cancellationToken));
            foreach (var port in scan.Ports)
                await connection.ExecuteAsync(new CommandDefinition(@"
INSERT INTO dbo.Discovery (HostJobId, HostId, DiscoveryType, DiscoveryDetail, PortNumber, ObservedAtUtc)
VALUES (@HostJobId, @HostId, 'Port', @Detail, @Number, @ObservedAtUtc);",
                    new { job.HostJobId, job.HostId, port.Number, port.ObservedAtUtc, Detail = $"{port.Protocol} {port.Detail}".Trim() },
                    transaction, cancellationToken: cancellationToken));
            await connection.ExecuteAsync(new CommandDefinition(@"
UPDATE dbo.HostJob SET State = 1, LeaseToken = NULL, LeaseUntil = NULL, LastError = NULL,
UpdatedAt = GETDATE() WHERE HostJobId = @HostJobId;", job, transaction, cancellationToken: cancellationToken));
            transaction.Commit();
        }

        public async Task FailAsync(ReconJob job, string error, bool cancelled, CancellationToken cancellationToken)
        {
            using var connection = new SqlConnection(_options.ConnectionString);
            await connection.ExecuteAsync(new CommandDefinition(@"
UPDATE dbo.HostJob SET State = @State, LastError = @Error, LeaseToken = NULL, LeaseUntil = NULL,
UpdatedAt = GETDATE() WHERE HostJobId = @HostJobId AND State = 2 AND LeaseToken = @LeaseToken;",
                new { job.HostJobId, job.LeaseToken, State = cancelled ? 0 : 3, Error = error },
                cancellationToken: cancellationToken));
        }
    }
}
