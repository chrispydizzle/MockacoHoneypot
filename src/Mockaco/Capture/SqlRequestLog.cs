using Dapper;
using Microsoft.Extensions.Options;
using System.Data.SqlClient;
using System.Threading;
using System.Threading.Tasks;

namespace Mockaco.Capture
{
    public sealed class SqlRequestLog : IRequestLog
    {
        private readonly string _connectionString;

        public SqlRequestLog(IOptions<HoneypotOptions> options) => _connectionString = options.Value.ConnectionString;

        public async Task WriteAsync(CapturedRequest request, CancellationToken cancellationToken)
        {
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            using var transaction = connection.BeginTransaction();
            // Serialize creation of one source, not requests from unrelated sources.
            const string sql = @"
DECLARE @SourceHostId bigint;
SELECT @SourceHostId = HostId FROM dbo.Host WITH (UPDLOCK, HOLDLOCK)
WHERE IpAddress = @SourceAddress;
IF @SourceHostId IS NULL
BEGIN
    INSERT dbo.Host (IpAddress) VALUES (@SourceAddress);
    SET @SourceHostId = SCOPE_IDENTITY();
END;
INSERT dbo.Request (SourceHostId, TargetHost, Target, Method, QueryString)
VALUES (@SourceHostId, @TargetHost, @Target, @Method, @QueryString);";
            await connection.ExecuteAsync(new CommandDefinition(sql, request, transaction,
                cancellationToken: cancellationToken));
            transaction.Commit();
        }
    }
}
