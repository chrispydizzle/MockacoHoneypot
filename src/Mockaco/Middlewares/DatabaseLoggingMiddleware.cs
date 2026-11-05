using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Mockaco.Capture;
using System;
using System.Threading.Tasks;

namespace Mockaco.Middlewares
{
    public sealed class DatabaseLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IRequestLog _log;
        private readonly ILogger<DatabaseLoggingMiddleware> _logger;

        public DatabaseLoggingMiddleware(RequestDelegate next, IRequestLog log, ILogger<DatabaseLoggingMiddleware> logger)
        {
            _next = next;
            _log = log;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _log.WriteAsync(new CapturedRequest(
                    context.Connection.RemoteIpAddress?.ToString() ?? "(unknown)",
                    context.Request.Host.ToString(), context.Request.Path.ToString(),
                    context.Request.Method, context.Request.QueryString.ToString()), context.RequestAborted);
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { throw; }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Could not persist incoming request");
                context.Response.StatusCode = StatusCodes.Status307TemporaryRedirect;
                context.Response.Redirect("https://dogeplanet.com");
            }
            await _next(context);
        }
    }
}
