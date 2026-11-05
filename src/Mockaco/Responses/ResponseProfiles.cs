using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Template;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Mockaco.Responses
{
    public sealed class ResponseProfiles
    {
        private readonly CompiledProfile[] _profiles;
        private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
        {
            Converters = { new JsonStringEnumConverter<HttpStatusCode>() },
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        };

        private ResponseProfiles(CompiledProfile[] profiles) => _profiles = profiles;

        public static ResponseProfiles Load(string directory)
        {
            var files = Directory.GetFiles(directory, "*.json", SearchOption.AllDirectories)
                .OrderBy(path => path, StringComparer.Ordinal).ToArray();
            if (files.Length == 0) throw new InvalidDataException($"No response profiles found in '{directory}'.");
            return Parse(files.Select(File.ReadAllText));
        }

        public static ResponseProfiles Parse(IEnumerable<string> documents)
        {
            var profiles = documents.SelectMany(document =>
            {
                var profile = JsonSerializer.Deserialize<Profile>(document, JsonOptions)
                    ?? throw new InvalidDataException("A response profile cannot be null.");
                if (profile.Request == null) throw new InvalidDataException("Each profile needs a request.");
                var methods = Aliases(profile.Request.Method, profile.Request.Methods, "method");
                var routes = Aliases(profile.Request.Route, profile.Request.Routes, "route");
                if (profile.Response == null) throw new InvalidDataException("Each profile needs a response.");
                if (profile.Response.Status is { } status && ((int)status < 100 || (int)status > 599))
                    throw new InvalidDataException("Response status must be an HTTP status code.");
                if (profile.Response.BodyFormat == "json")
                    GeneratedValues.Expand(profile.Response.Body);
                else
                {
                    if (profile.Response.BodyFormat is not ("text" or "base64")
                        || profile.Response.Body is not JsonValue value || !value.TryGetValue<string>(out var text))
                        throw new InvalidDataException("bodyFormat must be json, or text/base64 with a string body.");
                    try
                    {
                        profile.Response.LiteralBody = profile.Response.BodyFormat == "base64"
                            ? Convert.FromBase64String(text) : Encoding.UTF8.GetBytes(text);
                    }
                    catch (FormatException exception)
                    {
                        throw new InvalidDataException("Invalid base64 response body.", exception);
                    }
                }
                return routes.SelectMany(route =>
                {
                    var template = TemplateParser.Parse(route);
                    var defaults = new RouteValueDictionary();
                    foreach (var parameter in template.Parameters.Where(parameter => parameter.DefaultValue != null))
                        defaults.Add(parameter.Name, parameter.DefaultValue);
                    var matcher = new TemplateMatcher(template, defaults);
                    return methods.Select(method => new CompiledProfile(method, matcher, profile.Response));
                });
            }).ToArray();
            return new ResponseProfiles(profiles);
        }

        public ResponseDefinition Match(HttpRequest request) => _profiles.FirstOrDefault(profile =>
            string.Equals(profile.Method, request.Method, StringComparison.OrdinalIgnoreCase) &&
            profile.Matcher.TryMatch(request.Path, new RouteValueDictionary()))?.Response;

        private sealed record CompiledProfile(string Method, TemplateMatcher Matcher, ResponseDefinition Response);

        private static string[] Aliases(string single, string[] multiple, string name)
        {
            if (single != null && multiple != null)
                throw new InvalidDataException($"Use request.{name} or request.{name}s, not both.");
            var values = multiple ?? (single == null ? Array.Empty<string>() : new[] { single });
            if (values.Length == 0 || values.Any(string.IsNullOrWhiteSpace))
                throw new InvalidDataException($"Each profile needs at least one request.{name}.");
            return values;
        }

        public sealed class Profile
        {
            public RequestDefinition Request { get; set; }
            public ResponseDefinition Response { get; set; }
        }

        public sealed class RequestDefinition
        {
            public string Method { get; set; }
            public string Route { get; set; }
            public string[] Methods { get; set; }
            public string[] Routes { get; set; }
        }

        public sealed class ResponseDefinition
        {
            public HttpStatusCode? Status { get; set; }
            public Dictionary<string, string> Headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
            public JsonNode Body { get; set; }
            public string BodyFormat { get; set; } = "json";
            internal byte[] LiteralBody { get; set; }
        }
    }
}
