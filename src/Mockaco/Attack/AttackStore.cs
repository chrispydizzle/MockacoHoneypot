using Dapper;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Attack
{
    /// <summary>
    /// SQL operations for the attack tables.
    /// </summary>
    public sealed class AttackStore : IAttackStore
    {
        private readonly string _connectionString;

        public AttackStore(IOptions<AttackOptions> options)
        {
            _connectionString = options.Value.ConnectionString;
        }

        /// <summary>
        /// Gets all hosts that have nmap or shodan findings but no attack queued.
        /// </summary>
        public async Task<IReadOnlyList<HostWithFindings>> GetHostsWithFindingsAsync(int batchSize, CancellationToken cancellationToken)
        {
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);

            const string sql = @"
SELECT DISTINCT
    h.HostId,
    h.IpAddress,
    (SELECT COUNT(*) FROM dbo.Discovery d WHERE d.HostId = h.HostId AND d.DiscoveryType = 'Port') AS PortCount,
    (SELECT COUNT(*) FROM dbo.ReconEvidence e
     JOIN dbo.HostJob hj ON hj.HostJobId = e.HostJobId
     JOIN dbo.Job j ON j.JobId = hj.JobId
     WHERE hj.HostId = h.HostId AND j.Provider = 'Shodan') AS ShodanRecordCount,
    (SELECT STRING_AGG(CAST(d.DiscoveryDetail AS nvarchar(max)), ', ') FROM dbo.Discovery d
     WHERE d.HostId = h.HostId AND d.DiscoveryType = 'Port') AS PortDetails,
    (SELECT TOP (1) e.ResponseJson FROM dbo.ReconEvidence e
     JOIN dbo.HostJob hj ON hj.HostJobId = e.HostJobId
     JOIN dbo.Job j ON j.JobId = hj.JobId
     WHERE hj.HostId = h.HostId AND j.Provider = 'Shodan'
     ORDER BY e.RetrievedAtUtc DESC) AS ShodanData
FROM dbo.Host h
WHERE EXISTS (
    SELECT 1 FROM dbo.Discovery d WHERE d.HostId = h.HostId AND d.DiscoveryType = 'Port'
    UNION
    SELECT 1 FROM dbo.ReconEvidence e
    JOIN dbo.HostJob hj ON hj.HostJobId = e.HostJobId
    JOIN dbo.Job j ON j.JobId = hj.JobId
    WHERE hj.HostId = h.HostId AND j.Provider = 'Shodan'
)
AND NOT EXISTS (
    SELECT 1 FROM dbo.Attack a WHERE a.HostId = h.HostId AND a.Status = 0
)
ORDER BY h.HostId
OFFSET 0 ROWS FETCH NEXT @BatchSize ROWS ONLY;";

            var hosts = await connection.QueryAsync<HostWithFindings>(
                new CommandDefinition(sql, new { BatchSize = batchSize },
                    cancellationToken: cancellationToken));

            return new List<HostWithFindings>(hosts);
        }

        /// <summary>
        /// Queues an attack record for a host and returns the new AttackId.
        /// </summary>
        public async Task<long> CreateAttackAsync(string hostIpAddress, string attackName, int attackType = 0, CancellationToken cancellationToken = default)
        {
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            using var transaction = connection.BeginTransaction();

            // Upsert Host row
            const string upsertHostSql = @"
DECLARE @HostId bigint;
SELECT @HostId = HostId FROM dbo.Host WITH (UPDLOCK, HOLDLOCK)
WHERE IpAddress = @IpAddress;
IF @HostId IS NULL
BEGIN
    INSERT dbo.Host (IpAddress) VALUES (@IpAddress);
    SET @HostId = SCOPE_IDENTITY();
END;
SELECT @HostId;";

            var hostId = await connection.ExecuteScalarAsync<long>(
                new CommandDefinition(upsertHostSql, new { IpAddress = hostIpAddress },
                    transaction, cancellationToken: cancellationToken));

            // Insert Attack row
            const string insertAttackSql = @"
INSERT dbo.Attack (HostId, AttackName, AttackType, Status, CreatedAt, UpdatedAt)
VALUES (@HostId, @AttackName, @AttackType, 0, SYSUTCDATETIME(), SYSUTCDATETIME());
SELECT SCOPE_IDENTITY();";

            var attackId = await connection.ExecuteScalarAsync<long>(
                new CommandDefinition(insertAttackSql,
                    new { HostId = hostId, AttackName = attackName, AttackType = attackType },
                    transaction, cancellationToken: cancellationToken));

            transaction.Commit();
            return attackId;
        }

        /// <summary>
        /// Stores a strategy-level execution result for an attack.
        /// </summary>
        public async Task SaveStrategyResultAsync(long attackId, string attackName, bool success, string response, string errorMessage, CancellationToken cancellationToken)
        {
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            using var transaction = connection.BeginTransaction();

            await connection.ExecuteAsync(new CommandDefinition(@"
INSERT dbo.AttackResult (AttackId, AttackName, Success, Response, ErrorMessage)
VALUES (@AttackId, @AttackName, @Success, @Response, @ErrorMessage);",
                new { AttackId = attackId, AttackName = attackName, Success = success ? 1 : 0, Response = response, ErrorMessage = errorMessage },
                transaction, cancellationToken: cancellationToken));

            transaction.Commit();
        }

        /// <summary>
        /// Stores LLM research findings for an attack.
        /// </summary>
        public async Task SaveFindingsAsync(long attackId, IReadOnlyList<AttackFinding> findings, CancellationToken cancellationToken)
        {
            if (findings.Count == 0) return;

            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);

            const string sql = @"
INSERT dbo.AttackFinding (AttackId, FindingType, Severity, Title, Description, Evidence, Exploitable)
VALUES (@AttackId, @FindingType, @Severity, @Title, @Description, @Evidence, @Exploitable);";

            foreach (var f in findings)
            {
                await connection.ExecuteAsync(new CommandDefinition(sql,
                    new
                    {
                        AttackId = attackId,
                        f.FindingType,
                        Severity = f.Severity,
                        f.Title,
                        f.Description,
                        f.Evidence,
                        f.Exploitable
                    },
                    cancellationToken: cancellationToken));
            }
        }

        /// <summary>
        /// Stores the result of an attack execution.
        /// </summary>
        public async Task SaveAttackResultAsync(long attackId, bool success, string response, string errorMessage, CancellationToken cancellationToken)
        {
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            using var transaction = connection.BeginTransaction();

            // Upsert Attack row with status
            await connection.ExecuteAsync(new CommandDefinition(@"
UPDATE dbo.Attack
SET Status = CASE @Success WHEN 1 THEN 3 ELSE 4 END,
    Result = @Result,
    UpdatedAt = SYSUTCDATETIME()
WHERE AttackId = @AttackId;",
                new { AttackId = attackId, Success = success ? 1 : 0, Result = response },
                transaction, cancellationToken: cancellationToken));

            // Insert AttackResult row
            const string insertResultSql = @"
INSERT dbo.AttackResult (AttackId, Success, Response, ErrorMessage)
VALUES (@AttackId, @Success, @Response, @ErrorMessage);";

            await connection.ExecuteAsync(new CommandDefinition(insertResultSql,
                new
                {
                    AttackId = attackId,
                    Success = success ? 1 : 0,
                    Response = response,
                    ErrorMessage = errorMessage
                },
                transaction, cancellationToken: cancellationToken));

            transaction.Commit();
        }

        /// <summary>
        /// Marks an attack as being researched.
        /// </summary>
        public async Task MarkResearchingAsync(long attackId, CancellationToken cancellationToken)
        {
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);

            await connection.ExecuteAsync(new CommandDefinition(@"
UPDATE dbo.Attack SET Status = 1, UpdatedAt = SYSUTCDATETIME()
WHERE AttackId = @AttackId AND Status = 0;",
                new { AttackId = attackId }, cancellationToken: cancellationToken));
        }

        /// <summary>
        /// Gets the host IP address by ID.
        /// </summary>
        public async Task<string> GetIpAddressByIdAsync(long hostId, CancellationToken cancellationToken)
        {
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);

            return await connection.ExecuteScalarAsync<string>(new CommandDefinition(@"
SELECT IpAddress FROM dbo.Host WHERE HostId = @HostId;",
                new { HostId = hostId }, cancellationToken: cancellationToken));
        }
    }

    /// <summary>
    /// Interface for the attack SQL store (for DI and testing).
    /// </summary>
    public interface IAttackStore
    {
        Task<IReadOnlyList<HostWithFindings>> GetHostsWithFindingsAsync(int batchSize, CancellationToken cancellationToken);
        Task<long> CreateAttackAsync(string hostIpAddress, string attackName, int attackType = 0, CancellationToken cancellationToken = default);
        Task SaveFindingsAsync(long attackId, IReadOnlyList<AttackFinding> findings, CancellationToken cancellationToken);
        Task SaveAttackResultAsync(long attackId, bool success, string response, string errorMessage, CancellationToken cancellationToken);
        Task SaveStrategyResultAsync(long attackId, string attackName, bool success, string response, string errorMessage, CancellationToken cancellationToken);
        Task MarkResearchingAsync(long attackId, CancellationToken cancellationToken);
        Task<string> GetIpAddressByIdAsync(long hostId, CancellationToken cancellationToken);
    }
}
