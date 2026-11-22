using System.Data;
using System.Data.SqlClient;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Mockaco.Responses;

if (args.Length is < 2 or > 4)
    throw new ArgumentException("Usage: DecoyInventory <profiles-directory> <output.json> [top=50] [exclude-path=/SDK/webLanguage]. Set ConnectionStrings__HttpDb to override localhost/HttpDb.");

var top = args.Length > 2 ? int.Parse(args[2]) : 50;
if (top < 1) throw new ArgumentOutOfRangeException(nameof(top));
var excludePath = args.Length > 3 ? args[3] : "/SDK/webLanguage";
var files = Directory.GetFiles(args[0], "*.json", SearchOption.AllDirectories)
    .Where(path => Path.GetFileName(path) is not ("get.json" or "options.json"))
    .OrderBy(path => path, StringComparer.Ordinal).ToArray();
if (files.Length == 0) throw new InvalidDataException("No specific decoy profiles found.");
var profiles = ResponseProfiles.Parse(files.Select(File.ReadAllText));
using var connection = new SqlConnection(Environment.GetEnvironmentVariable("ConnectionStrings__HttpDb")
    ?? "Server=localhost;Database=HttpDb;Integrated Security=true;TrustServerCertificate=true");
await connection.OpenAsync();
var covered = new HashSet<string>(StringComparer.Ordinal);
using (var command = connection.CreateCommand())
{
    command.CommandText = """
        SELECT DISTINCT Method, CONVERT(nvarchar(max), Target) COLLATE Latin1_General_100_BIN2 AS Path
        FROM dbo.Request;
        """;
    using var reader = await command.ExecuteReaderAsync();
    while (await reader.ReadAsync())
    {
        var path = reader.GetString(1);
        var context = new DefaultHttpContext();
        context.Request.Path = new PathString(path);
        foreach (var method in new[] { reader.GetString(0), "GET", "HEAD" })
        {
            context.Request.Method = method;
            if (profiles.Match(context.Request) != null)
            {
                covered.Add(path);
                break;
            }
        }
    }
}
using (var command = connection.CreateCommand())
{
    command.CommandText = "CREATE TABLE #Covered (Path nvarchar(max) COLLATE Latin1_General_100_BIN2 NOT NULL);";
    await command.ExecuteNonQueryAsync();
}
using (var table = new DataTable())
{
    table.Columns.Add("Path", typeof(string));
    foreach (var path in covered) table.Rows.Add(path);
    using var copy = new SqlBulkCopy(connection) { DestinationTableName = "#Covered" };
    await copy.WriteToServerAsync(table);
}
using (var command = connection.CreateCommand())
{
    command.CommandText = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "UncoveredRequestPaths.sql"));
    command.Parameters.Add("@Top", SqlDbType.Int).Value = top;
    command.Parameters.Add("@ExcludePath", SqlDbType.NVarChar, -1).Value = excludePath;
    using var reader = await command.ExecuteReaderAsync();
    var json = new System.Text.StringBuilder();
    while (await reader.ReadAsync()) json.Append(reader.GetString(0));
    using var report = JsonDocument.Parse(json.ToString());
    await File.WriteAllTextAsync(args[1], JsonSerializer.Serialize(report.RootElement,
        new JsonSerializerOptions { WriteIndented = true }));
    Console.WriteLine($"Excluded {covered.Count} observed paths covered by specific decoys. Ranked {report.RootElement.GetArrayLength()} uncovered paths in SQL; saved {args[1]}.");
    foreach (var item in report.RootElement.EnumerateArray())
        Console.WriteLine($"{item.GetProperty("Requests").GetInt64(),8} {item.GetProperty("Path").GetString()}");
}
