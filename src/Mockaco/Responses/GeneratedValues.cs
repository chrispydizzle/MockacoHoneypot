using NaughtyStrings;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;

namespace Mockaco.Responses
{
    internal static class GeneratedValues
    {
        public static JsonNode Expand(JsonNode node)
        {
            if (node is JsonObject obj)
            {
                if (obj.TryGetPropertyValue("$generator", out var generator))
                {
                    var values = Values(generator?.GetValue<string>());
                    var count = obj["count"]?.GetValue<int>() ?? 1;
                    if (count < 1) throw new InvalidDataException("Generator count must be positive.");
                    return new JsonArray(Enumerable.Range(0, count)
                        .Select(_ => (JsonNode)JsonValue.Create(values[Random.Shared.Next(values.Count)])).ToArray());
                }
                return new JsonObject(obj.Select(pair => KeyValuePair.Create(pair.Key, Expand(pair.Value))));
            }
            if (node is JsonArray array) return new JsonArray(array.Select(Expand).ToArray());
            return node?.DeepClone();
        }

        private static IReadOnlyList<string> Values(string generator) => generator switch
        {
            "SQLInjection" => TheNaughtyStrings.SQLInjection,
            "ScriptInjection" => TheNaughtyStrings.ScriptInjection,
            "QuotationMarks" => TheNaughtyStrings.QuotationMarks,
            "RightToLeftStrings" => TheNaughtyStrings.RightToLeftStrings,
            "TrickUnicode" => TheNaughtyStrings.TrickUnicode,
            _ => throw new InvalidDataException($"Unknown response generator '{generator}'.")
        };
    }
}
