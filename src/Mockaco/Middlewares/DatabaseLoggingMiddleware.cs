using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Data.SqlClient;
using System.Threading.Tasks;

namespace Mockaco.Middlewares
{
    public class DatabaseLoggingMiddleware : BaseReconGrabbingMiddleware
    {
        private readonly RequestDelegate _next;

        public DatabaseLoggingMiddleware(RequestDelegate next)
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
                using (var connection = new SqlConnection(@"Data Source=(LocalDB)\MSSQLLocalDB;AttachDbFilename=E:\Hacking\httpdb.mdf;Integrated Security=True;Connect Timeout=30"))
                {
                    connection.Open();
                    var sql = @"DECLARE @SourceHostId BIGINT
                                SET @SourceHostId = (SELECT HostId FROM Host WHERE IpAddress = @SourceHost)
                                IF @SourceHostId IS NULL 
                                    BEGIN
                                        INSERT INTO Host (IpAddress) VALUES (@SourceHost)
                                        SET @SourceHostId = SCOPE_IDENTITY()
                                    END
                                INSERT INTO Request (SourceHostId, TargetHost, Target, Method, QueryString)
                                VALUES (@SourceHostId , @TargetHost, @Target, @Method, @QueryString)";
                    using var command = new SqlCommand(sql, connection);
                    command.Parameters.Add(new SqlParameter("SourceHost", httpContext.Connection.RemoteIpAddress.ToString()));
                    command.Parameters.Add(new SqlParameter("TargetHost", httpContext.Request.Host.ToString()));
                    command.Parameters.Add(new SqlParameter("Target", httpContext.Request.Path.ToString()));
                    command.Parameters.Add(new SqlParameter("Method", httpContext.Request.Method));
                    command.Parameters.Add(new SqlParameter("QueryString", httpContext.Request.QueryString.ToString()));
                    await command.ExecuteNonQueryAsync();

                }
                await _next(httpContext);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error doing the DB thing.");
            }
        }
    }
}
