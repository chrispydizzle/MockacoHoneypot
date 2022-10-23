using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Data.SqlClient;
using System.Threading.Tasks;

namespace Mockaco
{
    public class DatabaseLoggingMiddleware
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
                    var sql = "INSERT INTO Request (SourceHost, TargetHost, Target, Method, QueryString) VALUES (@SourceHost, @TargetHost, @Target, @Method, @QueryString)";
                    using (var command = new SqlCommand(sql, connection))
                    {
                        command.Parameters.Add(new SqlParameter("SourceHost", httpContext.Connection.RemoteIpAddress.ToString()));
                        command.Parameters.Add(new SqlParameter("TargetHost", httpContext.Request.Host.ToString()));
                        command.Parameters.Add(new SqlParameter("Target", httpContext.Request.Path.ToString()));
                        command.Parameters.Add(new SqlParameter("Method", httpContext.Request.Method));
                        command.Parameters.Add(new SqlParameter("QueryString", httpContext.Request.QueryString.ToString()));
                        await command.ExecuteNonQueryAsync();
                    }
                    
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
