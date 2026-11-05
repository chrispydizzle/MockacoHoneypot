using Mockaco.Analytics;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
if (string.IsNullOrEmpty(builder.Configuration["urls"]))
    builder.WebHost.UseUrls("http://127.0.0.1:15004");
builder.Services.AddSingleton<AnalyticsStore>();
builder.Services.AddSingleton<IntelligenceStore>();
builder.Services.AddSingleton<HostMaintenanceStore>();
builder.Services.AddResponseCompression(options => options.EnableForHttps = true);
var app = builder.Build();
app.UseResponseCompression();
app.Use(async (context, next) =>
{
    try { await next(context); }
    catch (ArgumentException exception)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new { error = exception.Message });
    }
    catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { }
    catch (Exception exception)
    {
        app.Logger.LogError(exception, "Could not complete analytics request");
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await context.Response.WriteAsJsonAsync(new
        {
            error = "Could not complete this request. Check SQL Server, ConnectionStrings__HttpDb, and the server log."
        });
    }
});
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapGet("/api/intelligence", async (string? query, string? status, string? sort, int? page,
    IntelligenceStore store, CancellationToken cancellationToken) =>
    Results.Ok(await store.CollectionAsync(query, status ?? "all", sort ?? "last-seen", page ?? 0, cancellationToken)));
app.MapGet("/api/intelligence/non-public-hosts", async (HostMaintenanceStore store,
    CancellationToken cancellationToken) => Results.Ok(await store.PreviewAsync(cancellationToken)));
app.MapPost("/api/intelligence/non-public-hosts/purge", async (HostPurgeRequest request,
    HostMaintenanceStore store, CancellationToken cancellationToken) =>
    Results.Ok(await store.PurgeAsync(request.HostIds, cancellationToken)));
app.MapGet("/api/sources/{hostId:long}/evidence/{hostJobId:long}", async (long hostId, long hostJobId,
    bool? download, IntelligenceStore store, CancellationToken cancellationToken) =>
{
    var json = await store.EvidenceAsync(hostId, hostJobId, cancellationToken);
    if (json is null) return Results.NotFound(new { error = "Evidence not found for this host and job." });
    return download == true
        ? Results.File(Encoding.UTF8.GetBytes(json), "application/json", $"evidence-{hostId}-{hostJobId}.json")
        : Results.Content(json, "application/json", Encoding.UTF8);
});
app.MapGet("/api/sources/{hostId:long}/requests", async (long hostId, long? cursor,
    IntelligenceStore store, CancellationToken cancellationToken) =>
    Results.Ok(await store.RequestsAsync(hostId, cursor, cancellationToken)));
app.MapGet("/api/snapshot", async (string? from, string? before, bool? refresh, AnalyticsStore store,
    CancellationToken cancellationToken) =>
{
    var analysis = await store.GetAsync(AnalysisWindow.Parse(from, before), refresh ?? false, cancellationToken);
    return Results.Ok(analysis.Snapshot);
});
app.MapGet("/api/sources/{hostId:long}", async (long hostId, string? from, string? before, long? cursor,
    AnalyticsStore store, CancellationToken cancellationToken) =>
{
    if (cursor is <= 0) return Results.BadRequest(new { error = "Request cursor must be positive." });
    var source = await store.SourceAsync(hostId, AnalysisWindow.Parse(from, before), cursor, cancellationToken);
    return source is null ? Results.NotFound(new { error = "Source not found." }) : Results.Ok(source);
});
app.MapGet("/api/sources/{hostId:long}/neighbors", async (long hostId, string? from, string? before,
    int? count, AnalyticsStore store, CancellationToken cancellationToken) =>
{
    var analysis = await store.GetAsync(AnalysisWindow.Parse(from, before), false, cancellationToken);
    if (!analysis.Snapshot.Sources.Any(source => source.HostId == hostId))
        return Results.NotFound(new { error = "Source not present in this date window." });
    return Results.Ok(analysis.Neighbors(hostId, count ?? 8));
});
app.Run();
