# Behavior Atlas and Honeypot Collector

A small HTTP honeypot that records requests in SQL Server, observes source-host
services through background Nmap scans and optional Shodan host lookups, and visualizes the capture in the
separate Behavior Atlas dashboard.

This started as a fork of [Mockaco](https://github.com/natenho/Mockaco). The
general-purpose mock-server engine has been removed: no C# scripting compiler,
Bogus integration, callbacks, global template state, verification API, or
XML/form/binary response machinery. The `Mockaco` project paths and executable
name remain so existing build, launch, and benchmark commands still work.

## Components

| Path | Purpose |
|---|---|
| `src\Mockaco` | Request capture, small response profiles, and recon worker |
| `src\Mockaco.Analytics` | Intelligence inventory, host dossiers, behavior atlas, and explicit host cleanup |
| `HttpLog` | Existing SQL Server schema and recon lease migration |
| `tools\ReconBenchmark` | Isolated SQL/Nmap concurrency and correctness checks |
| `tools\CollectorChecks` | Published-application, SQL capture, and atlas integration checks |
| `tools\ShodanChecks` | Offline Shodan fixtures, provider-isolated SQL queues, and atlas provenance checks |
| `tools\RequestInventory.sql` | Read-only request-shape frequencies, source counts, and recent traffic |

The .NET solution builds without the old sibling SaltwaterTaffy checkout or
Visual Studio SQL tooling. Deploy `HttpLog\HttpLog.sqlproj` separately using
SQL Server Data Tools; it is not part of the application build.

## Run locally

Install the .NET 10 SDK, SQL Server with the `HttpLog` schema deployed to `HttpDb`,
and Nmap on PATH for recon. `global.json` selects a stable .NET 10 SDK.

```powershell
dotnet run --project .\src\Mockaco\Mockaco.csproj -- --urls http://127.0.0.1:15003
dotnet run --project .\src\Mockaco.Analytics\Mockaco.Analytics.csproj
```

Run these applications in separate terminals. The dashboard defaults to
`http://127.0.0.1:15004`; `GET /ping` on the collector returns HTTP 200 with no
body. Its development launch profile still binds port 15003 on all interfaces
when `--urls` is omitted. The background worker scans recorded source addresses
when the database contains job definitions, independently of incoming requests.

Both applications use local `HttpDb` and Windows integrated authentication by
default. `ConnectionStrings__HttpDb` overrides the collector, recon, and analytics
connection. Existing `Recon__ConnectionString` remains supported for a separate
recon connection when the shared override is absent; capture can similarly use
`Honeypot__ConnectionString`.

Collector settings are loaded from `Settings` beside the executable, followed by
environment-specific settings, environment variables, and command-line overrides.
Profiles are also resolved relative to the executable, so published builds do not
depend on the caller's working directory. Absolute paths are supported.

## Response profiles

Profiles live in `src\Mockaco\Profiles`. The original response families remain
as fallbacks after the more specific decoy profiles:

| Method and route | Response |
|---|---|
| `GET /{action}` | 200, empty body when no earlier profile matches |
| `OPTIONS /{action}` | 204, existing CORS headers |
| `POST /` | JSON-RPC envelope with eight SQL test strings |
| `POST /json_rpc` | JSON-RPC envelope with SQL, quotation, RTL, and Unicode sample groups |
| `POST /eh/{action}/` | JSON-RPC envelope with eight script-injection test strings |

Routes use ASP.NET route-template matching: `/{action}` matches one path segment,
not an arbitrary nested path. Nonmatching requests are still recorded and return
501 by default. `Honeypot:DefaultStatusCode`, `Honeypot:UnmatchedStatusCode`, and
`Honeypot:DefaultContentType` configure the response defaults.

Profiles are ordinary JSON, loaded in filename order at startup; first match wins.
Restart the collector after editing them. Use `--path C:\path\to\Profiles` or
`Honeypot__ProfilesPath` to select another directory. For example:

```json
{
  "request": { "method": "POST", "route": "/example" },
  "response": {
    "status": "OK",
    "headers": { "Content-Type": "application/json" },
    "body": {
      "id": 1,
      "jsonrpc": "2.0",
      "result": [ { "$generator": "SQLInjection", "count": 8 } ]
    }
  }
}
```

Status accepts a numeric HTTP code or a `System.Net.HttpStatusCode` name.
Bodies default to JSON values. Each `$generator` object expands to an array of randomly
selected strings from the retained NaughtyStrings corpus; supported generators
are `SQLInjection`, `ScriptInjection`, `QuotationMarks`, `RightToLeftStrings`, and
`TrickUnicode`. Other JSON content stays literal; it is not evaluated as C#.

For literal responses, set `bodyFormat` to `text` and supply a string `body`;
newlines and quotes are emitted as bytes, not as a JSON-quoted string.
`bodyFormat: "base64"` decodes a string body into bytes, used for the favicon.
Text and binary bodies are prepared at startup. JSON remains the default, so
existing JSON string bodies keep their serialization behavior. No format reads
files named by an incoming request or evaluates scripts.

Use either `method` or `methods`, and either `route` or `routes`, to share one
response across explicit aliases. For example:

```json
{
  "request": {
    "methods": ["GET", "HEAD"],
    "routes": ["/.git/config", "/{directory}/.git/config"]
  },
  "response": {
    "status": 200,
    "headers": { "Content-Type": "text/plain; charset=utf-8" },
    "bodyFormat": "text",
    "body": "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
  }
}
```

HEAD must be listed to match a profile. Its status and representation headers
match GET, including the byte `Content-Length`, but no body is sent.

### Observed-request decoys

The `00-*.json` files take precedence over the generic GET fallback. They cover
the observed config-discovery requests and common paths from the request
database, using a fictional Northstar Portal installation:

| Request family | Representation |
|---|---|
| `/.env`, production/backup variants, `/{directory}/.env` | Production-style dotenv with MySQL, Redis, SMTP, and synthetic AWS values |
| Development, staging/UAT, test/CI, and example dotenv variants | Environment-appropriate settings rather than the same response for every suffix |
| `/.git/config`, `/{directory}/.git/config` | Git INI with origin and main-branch tracking; includes `assets..`, `media..`, and `static..` prefixes |
| `/.aws/credentials`, `/.aws/config`, `/config.json` | Consistent INI/JSON configuration |
| `/docker-compose.prod.yml`, `.yml` and `.yaml` variants | Compose YAML for nginx, the portal, MySQL, and Redis |
| `/`, index/landing aliases, login paths, `/bbs/forum.php` | HTML pages and forms; login submissions never authenticate |
| `/captcha`, `/favicon.ico`, `/robots.txt`, `/sitemap.xml` | SVG, real ICO bytes, crawler text, and XML |
| `/cgi-sys/defaultwebpage.cgi`, PHP info paths | Hosting and PHP diagnostic-style HTML |
| `/wp-login.php`, WordPress manifest paths, `/xmlrpc.php` | Login HTML, WLW XML, GET 405/Allow header, and a static POST XML-RPC fault |
| Tomcat manager, `/hudson`, `/geoserver/web/` | Basic-auth challenge, Jenkins-style denial, and GeoServer-style landing page |
| `/developmentserver/metadatauploader` | SAP-style `FAILED` / `Cause` text for GET/HEAD/POST; a synthetic error stub, not an upload service |
| `/actuator/health`, `/version`, `/api.php` | JSON health/version and unauthenticated API responses |

These are bounded static decoys, not running WordPress, Tomcat, Jenkins, PHP,
or GeoServer installations. POST login/XML-RPC/metadata-uploader responses do not
parse submissions or implement those protocols. The metadata-uploader profile
never saves or executes uploads. Request-body logging remains unchanged.
All apparent passwords, keys, hostnames, and configuration data in these profiles
are invented fixtures; they are not taken from local files, environment variables,
or real accounts. Keep the fixture values consistent when customizing the persona.
Unlisted paths and methods retain the existing fallback behavior.

To choose additional profiles from a current capture, run the reusable inventory:

```powershell
New-Item -ItemType Directory -Force .\artifacts | Out-Null
sqlcmd -S localhost -E -d HttpDb -b -r1 -v Top=100 -i .\tools\RequestInventory.sql -y0 -w65535 -f65001 -o .\artifacts\request-inventory.json
```

The JSON reports all-time frequency, distinct known source counts, and the last
30 days using the database clock. Paths retain their case and requests are not
deduplicated. The query changes no application data; its intermediate table is
session-local. Source counts are all-time, including on the recent list.
Use both frequency and source breadth: one repeat source can dominate raw counts.

The old templates interpolated enumerable type names and discarded some generator
results. These profiles emit actual sample arrays inside the same
`id`/`jsonrpc`/`result` envelope. Legacy local `Mocks` files are not deleted, read,
or included in published builds. They must be translated to this profile format;
this is deliberately not a replacement implementation of the Mockaco language.

Capture writes the source address, target host, case-preserving path, method,
query string, and database-default timestamp before responding. It does not parse
or store bodies or headers, matching the existing SQL capture scope. Concurrent
first requests share one source record. A failed database write returns 503
rather than the old middleware's misleading empty 200. The retired
`/_mockaco/verification` path is now an ordinary captured, unmatched request.

## Build and publish

```powershell
dotnet build .\Mockaco.sln -c Release
dotnet test .\Mockaco.sln -c Release
node --test .\test\Mockaco.Analytics.Tests\dashboard.test.mjs
dotnet publish .\src\Mockaco\Mockaco.csproj -c Release -o .\artifacts\collector-publish
dotnet .\artifacts\collector-publish\Mockaco.dll --urls http://127.0.0.1:15003
```

The published collector requires the ASP.NET Core Runtime 10 and includes its
settings and profiles. It is no longer packaged as the upstream `mockaco` NuGet
tool. CI builds/tests the applications and produces artifacts; it does not
automatically publish packages, Docker images, or GitHub releases.

To check a published collector against a disposable SQL database:

```powershell
dotnet run --project .\tools\CollectorChecks -c Release -- --app .\artifacts\collector-publish\Mockaco.dll
```

This starts its own collector on an ephemeral loopback port, sends concurrent
requests, checks the original profiles plus every case in
`test\Mockaco.Tests\Responses\DecoyRequests.json` (including HEAD parity, native
content types, and binary/XML/JSON bodies), checks capture failure handling, and
reads the resulting records through the analytics store. It creates no scan job
definitions and never uses the live `HttpDb`. The SQL account needs create/drop
database permission; `--sql` overrides the master connection. The owned process
and temporary database are removed on completion. Representative received
dotenv, Compose, Git, and icon bodies are retained under the ignored
`artifacts\collector-responses` directory.

## Recon worker and concurrency

Before starting this version against an existing database, apply the additive,
rerunnable migration (stop old server instances first):

```powershell
sqlcmd -S localhost -E -d HttpDb -b -i .\HttpLog\Migrations\001-ReconLeases.sql
sqlcmd -S localhost -E -d HttpDb -b -i .\HttpLog\Migrations\002-ShodanLookup.sql
```

Fresh deployments of `HttpLog.sqlproj` already include these columns.
Configure `Recon` in `src\Mockaco\Settings\appsettings.json`, or use environment
variables such as `$env:Recon__Workers = '16'`. Workers default to eight; there is no
hard-coded concurrency ceiling. Each worker owns one asynchronous Nmap process.
The default profile remains 5,000 TCP ports, `-Pn -sV --version-all -O`, with a
10-minute Nmap host timeout and an 11-minute process deadline. `Recon:Ports`
optionally replaces `TopPorts` with an explicit Nmap port list.

### Shodan host lookups

Shodan is disabled until `Shodan__ApiKey` is set in the collector's environment.
Supply the real key locally, not in source control or command-line arguments.
The worker calls only `GET https://api.shodan.io/shodan/host/{ip}` with
`history=false&minify=false`: this retrieves existing records, **not an on-demand
scan**. It does not submit targets to the scan API or spend scan credits.
Shodan account permissions still apply.

Stop **all old collectors** before migrating and upgrading: old workers do not
understand providers and could run Nmap against Shodan jobs. Upgrade the atlas
against the migrated database too. Migration 002 is additive and repeatable;
existing job definitions become `Nmap`, and fresh SSDT deployments include the
same schema.

Once configured, the Shodan worker creates its job definition and lazily queues
one lookup per host in the recon database, including existing hosts and newly
captured addresses. Nmap and Shodan cannot claim each other's jobs. Completed
lookups are not refreshed automatically. No requests are sent directly to those
hosts by the Shodan worker. Its connection defaults to the recon connection;
`Shodan__ConnectionString` can override it, unless `ConnectionStrings__HttpDb`
is set (the shared setting takes precedence).

| Setting | Default | Behavior |
|---|---|---|
| `Shodan__RequestIntervalSeconds` | `1` | Minimum delay between lookups in this process |
| `Shodan__RequestTimeoutSeconds` | `30` | HTTP request deadline |
| `Shodan__PollIntervalSeconds` | `2` | Idle queue polling |
| `Shodan__RetryDelaySeconds` | `15` | Initial transient-error backoff |
| `Shodan__MaxRetryDelaySeconds` | `300` | Exponential-backoff ceiling; a longer `Retry-After` wins |

Use one active Shodan worker process per API key, or coordinate your aggregate
request rate externally. HTTP 429, 408, 5xx, network failures, timeouts, and
malformed responses release the job back to pending and retry with backoff.
HTTP 401/403 releases the job and pauses only Shodan until the collector is
restarted with working credentials/permissions. Other rejected requests fail
that job. Shutdown cancels the HTTP request and releases its lease; an abandoned
lease expires and can be reclaimed. A Shodan `404` with "No information available
for that IP." completes as no-data, rather than retrying forever.

`dbo.ReconEvidence` retains the full JSON response, HTTP status, and retrieval
timestamp, keyed by `HostJobId`. Banners, CVEs, organization, location, and other
returned fields remain in that JSON. Hostnames and services also populate the
existing discovery tables. The atlas labels their provider and shows Shodan's
per-banner observation timestamp separately from retrieval time; **retrieving
old Shodan data is not a fresh scan or a confirmed vulnerability**. Raw JSON
is available in the host dossier, loaded separately from the collection payload.

Offline verification, using fake HTTP responses and an owned disposable SQL
database (no API key or external scan required):

```powershell
dotnet test .\test\Mockaco.Tests -c Release --filter "FullyQualifiedName~Shodan|FullyQualifiedName~ReconWorkerTest"
dotnet run --project .\tools\ShodanChecks -c Release
```

`ShodanChecks` accepts `--sql` for a master connection with create/drop database
permission. It removes only its own uniquely named database. `CollectorChecks`
explicitly disables Shodan in its child process even if the parent has a key.

Claims are serialized briefly inside SQL transactions, not during scans.
Job states are 0=pending, 1=completed (unchanged), 2=running, 3=failed.
Running jobs have an owner token and an expiring lease; a restarted worker
reclaims abandoned jobs after expiry. Shutdown kills and awaits child processes
and returns owned jobs to pending. Failed jobs retain `LastError` and are not
silently retried forever. To explicitly retry a failed job:

```sql
UPDATE dbo.HostJob SET State = 0, LastError = NULL WHERE HostJobId = <id> AND State = 3;
```

Results and completion are committed together; stale owners cannot publish results.
Only ports reported as `open` are saved. Nmap must be on PATH; OS detection
requires the usual Nmap/Npcap privileges on Windows. The SaltwaterTaffy dependency
is no longer needed.

### Repeatable recon benchmark

```powershell
dotnet run --project .\tools\ReconBenchmark -c Release -- --repetitions 2 --targets 16
```

This exercises the real worker, SQL claim/result path, and Nmap at 2/4/8/16 workers.
It creates and removes its own uniquely named SQL database and loopback HTTP
listeners; it never reads visitor targets from `HttpDb`. It checks concurrent
claims, stale-lease fencing, migration repeatability, cancellation, failures,
and open/closed port controls. The SQL account needs permission to create/drop
the isolated benchmark database.

The default controlled profile scans ports 8080 (owned HTTP service) and 8081
(closed), preserving exhaustive service and OS detection. This isolates concurrency
without spending minutes probing unrelated wildcard-bound services on the host.
It is not a production 5,000-port throughput prediction. Add `--full-profile`
to use the unchanged production port set; this also probes existing local services
and can take substantially longer. `--sql` selects a SQL connection;
`--output` selects the JSON results file (default `tools\ReconBenchmark\results.json`).
Results include throughput, p95 scan duration, observed process concurrency,
failures, missed HTTP services, closed-port discoveries, and duplicate claims.
Use `--verify-only` to repeat integration checks and the positive-control scan
without rerunning the timed benchmark.

### Recon atlas

Run the separate analytics dashboard:

```powershell
dotnet run --project .\src\Mockaco.Analytics\Mockaco.Analytics.csproj
```

Open `http://127.0.0.1:15004`. The dashboard connects to local `HttpDb` using
Windows authentication; override it with `ConnectionStrings__HttpDb`, or use
`--urls` to change the listening address. It does not run the honeypot or recon
worker, change the schema, contact captured hosts, or require external web assets.
Use SQL Server 2017 or later with database compatibility level 130 or later
and apply migrations 001 and 002 before running against an existing database.

The default **Intelligence** view covers every stored host, including hosts
without captured HTTP requests. It shows collection totals, Shodan coverage,
reported countries and organizations, and a 50-row paginated inventory.
Search IP, organization, ISP, ASN, country, city, OS, domain, hostname or CVE;
filter by lookup state, reported CVEs or observed ports; sort by latest request,
request volume, port count or CVE count. Geography and organization rankings
are clickable filters. Totals and rankings always describe the whole collection.

Open a source for its **Overview**, **Services**, **CVEs**, **Traffic** and
**Raw evidence** dossier. Service records retain Nmap/Shodan provenance,
observation/retrieval times, banners, HTTP/TLS/SSH metadata and original fields.
CVEs show provider-supplied scores and verification flags, not independent
findings. Requests retain original queries and page back through all traffic.
Full stored JSON can be viewed or downloaded, including responses with no host
information. Large lists render incrementally without discarding evidence.
URLs preserve the selected host and dossier tab; Escape closes the dossier
and arrow keys navigate tabs. The latest stored Shodan response is fetched when
a dossier opens; older responses are fetched on demand.

The read-only endpoints are `GET /api/intelligence` (`query`, `status`, `sort`,
zero-based `page`), `GET /api/sources/{hostId}/requests` (`cursor`) and
`GET /api/sources/{hostId}/evidence/{hostJobId}` (`download=true` for a file).
There is no refresh timer or dashboard generation batch. **Refresh collection**
rereads SQL immediately; loading the inventory or changing its filters/page
also reads current data. **Behavior atlas > Refresh data** rebuilds the cached
behavior analysis from SQL. Neither requires a build, publish, or collector
restart. The collector captures traffic and processes new recon work while
running, but completed Nmap/Shodan jobs are not automatically repeated.
Refreshing the dashboard does not rescan hosts or retrieve new Shodan results.
Close and reopen a dossier to reread its stored evidence.

**Clean up hosts** previews malformed and non-public addresses, including
private/local, shared, documentation, benchmark, multicast and reserved ranges.
It shows every matching address with its reason and the linked record counts.
**Purge hosts and linked data** permanently deletes that reviewed set of host
IDs and their requests, headers, recon jobs, service observations, hostnames and
raw recon evidence in one transaction. The server rechecks addresses before
deleting and rejects any public host in a submitted selection. Public hosts and
shared job definitions remain intact. Failed transactions roll back all deletes.

Cleanup follows the [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/)
and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) special-purpose
ranges, with multicast/reserved IPv6 handling. IPv4-mapped IPv6 addresses use the
embedded IPv4 classification. Public exceptions and conditionally routable
Teredo/6to4 addresses are retained; this is not a live routing/reachability test.
The cleanup API is `GET /api/intelligence/non-public-hosts` for the preview and
`POST /api/intelligence/non-public-hosts/purge` with JSON `{"hostIds":[...]}` for
the explicit deletion. Purging requires SQL DELETE permission; browsing and
refresh remain read-only.

After a successful purge the inventory reloads and the behavior cache is
invalidated, so the Behavior atlas rebuilds on its next opening. Hosts added
after the preview are not silently included. Linked counts can grow while the
collector receives traffic. Cleanup does not block future capture: traffic
from the same private address can create a new host record again. Other open
dashboard tabs or separate analytics processes still need their own refresh.

Select **Behavior atlas** for the existing traffic exploration workspace:

The constellation groups sources by normalized route/method sets, with an
individual-source view, pan/zoom, and optional separation of overlapping points.
Pan by dragging, arrow keys, or the **Pan view** direction buttons.
Coordinates use centered PCA on normalized, log-count TF-IDF profiles; the
display reports retained variance. Source details show exact full-profile cosine
similarities, raw requested paths, paginated requests, hostnames, and full service
banners. Similar behavior is not attribution. Timing and request order are not
part of this fingerprint.

The linked matrix counts distinct sources per requested endpoint family and
observed service. Sources can belong to multiple rows/columns. IP search, minimum
requests, and fingerprint selection define the matrix cohort; selecting a cell
highlights its sources without changing the denominator. Count and row-percentage
views and service search cover all observed services. The matrix renders eight
service columns per page; use the arrows or page picker to reach any page, and
scroll within the table when needed. Paging never changes counts, row
denominators, heat scales, or the selected cohort.
Missing observations are separate from unidentified or `tcpwrapped` services.

Dates filter incoming requests using the database clock: From is inclusive and
Before is exclusive. Service observations span all stored recon results, even
when request dates are filtered; their timestamps are job-update times. The
server caches the last requested date window in memory; **Refresh data** explicitly
reloads it. All sources in the window participate, without sampling.

Run the focused analytics checks:

```powershell
dotnet test .\test\Mockaco.Analytics.Tests\Mockaco.Analytics.Tests.csproj
node --test .\test\Mockaco.Analytics.Tests\dashboard.test.mjs .\test\Mockaco.Analytics.Tests\intelligence.test.mjs
```

For live browser checks against this populated capture, with the dashboard
running and `agent-browser` installed:

```powershell
agent-browser --session atlas-check open http://127.0.0.1:15004
$checks = Get-Content -Raw .\test\Mockaco.Analytics.Tests\browser-checks.js
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($checks))
agent-browser --session atlas-check eval -b $encoded
agent-browser --session atlas-check close
```

The same browser-evaluation command can run
`test\Mockaco.Analytics.Tests\ui-polish-checks.js` for service-page navigation,
focus, touch targets, pointer panning, and responsive layout. Run it on a fresh
all-time view. `tools\MeasureAtlasUi.js` measures matrix selection and service
search through the next paint; use the same viewport and capture when comparing
runs. These timings are a local interaction benchmark, not Web Vitals INP.
`test\Mockaco.Analytics.Tests\intelligence-browser-checks.js` uses offline API
fixtures to exercise inventory paging/filtering, dossiers, keyboard navigation,
full evidence, empty/error states and stale-response races. Run it at desktop
and mobile viewport sizes. `tools\ShodanChecks` also checks the intelligence
queries, literal search, evidence ownership and request paging in its owned SQL
database. It also checks non-public classification, transactional cleanup,
public-host rejection, cache invalidation and late-worker handling.
`test\Mockaco.Analytics.Tests\host-cleanup-browser-checks.js` uses offline
fixtures for preview/purge failures, exact selection, full candidate browsing,
focus, mobile layout and post-purge refresh; it never writes to the real database.

To include the published cleanup HTTP endpoints in the owned-database checks:

```powershell
dotnet publish .\src\Mockaco.Analytics\Mockaco.Analytics.csproj -c Release -o .\artifacts\host-cleanup-publish
dotnet run --project .\tools\ShodanChecks -c Release -- --app .\artifacts\host-cleanup-publish\Mockaco.Analytics.dll
```

The harness starts and stops its own loopback analytics process and drops only
its own uniquely named database.

## License and attribution

Apache License 2.0; see [LICENSE](LICENSE) for the original Mockaco attribution
and dependency notices. Removing the framework does not remove upstream credit.
