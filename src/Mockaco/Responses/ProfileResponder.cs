using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Mockaco.Responses
{
    public sealed class ProfileResponder
    {
        private readonly ResponseProfiles _profiles;
        private readonly HoneypotOptions _options;
        private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

        public ProfileResponder(ResponseProfiles profiles, IOptions<HoneypotOptions> options)
        {
            _profiles = profiles;
            _options = options.Value;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var profile = _profiles.Match(context.Request);
            context.Response.StatusCode = profile?.Status is { } status ? (int)status
                : profile == null ? _options.UnmatchedStatusCode : _options.DefaultStatusCode;
            if (profile?.Headers != null)
                foreach (var header in profile.Headers) context.Response.Headers[header.Key] = header.Value;
            context.Response.ContentType ??= profile?.BodyFormat switch
            {
                "text" => "text/plain; charset=utf-8",
                "base64" => "application/octet-stream",
                _ => _options.DefaultContentType
            };
            var body = profile == null
                ? Encoding.UTF8.GetBytes("""[{"message":"Incoming request didn't match any profile"}]""")
                : profile.LiteralBody ?? (profile.Body == null ? Array.Empty<byte>()
                    : Encoding.UTF8.GetBytes(GeneratedValues.Expand(profile.Body).ToJsonString(JsonOptions)));
            context.Response.ContentLength = body.Length;
            if (!HttpMethods.IsHead(context.Request.Method) && body.Length != 0)
                await context.Response.Body.WriteAsync(body, context.RequestAborted);
        }
    }
}
