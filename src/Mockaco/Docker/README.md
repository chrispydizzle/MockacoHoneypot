# Honeypot collector container

Build the collector image from the repository root:

```powershell
docker build -f .\src\Mockaco\Docker\Dockerfile -t behavior-atlas-collector .
```

The image contains the ASP.NET Core 10 runtime, the bundled response profiles,
collector settings, and Nmap. It does not include SQL Server or the separate
Behavior Atlas dashboard, and it is not the upstream `natenho/mockaco` image.

## Run

Deploy the `HttpLog` schema and recon lease migration before starting the
collector. Set `ConnectionStrings__HttpDb` in your shell to a SQL Server
connection string reachable from the container, then pass it through:

```powershell
docker run --rm --name behavior-atlas-collector -p 15003:5000 -e ASPNETCORE_URLS=http://+:5000 -e ConnectionStrings__HttpDb behavior-atlas-collector
```

The default Windows integrated-authentication connection is not suitable for
this Linux container without additional authentication setup. `localhost` inside
the container refers to the container, not the host's SQL Server; on Docker
Desktop, use `host.docker.internal` to reach a host service.

`GET http://localhost:15003/ping` returns an empty 200 response after recording
the request. Failed SQL writes return 503. The shared connection override is used
by both capture and recon.

The recon worker scans recorded source addresses when the database contains
job definitions, independently of incoming requests. Its network visibility and
source addresses depend on your container networking. Nmap OS detection also
requires the appropriate runtime network privileges; the image does not grant
them automatically.

## Customize profiles and settings

Mount a directory of profile JSON files at `/app/Profiles`. For example, from the
repository root:

```powershell
docker run --rm --name behavior-atlas-collector -p 15003:5000 -e ASPNETCORE_URLS=http://+:5000 -e ConnectionStrings__HttpDb --mount "type=bind,source=$((Resolve-Path .\src\Mockaco\Profiles).Path),target=/app/Profiles,readonly" behavior-atlas-collector
```

Profiles load in filename order at startup; restart after changing them. They
support route/method aliases, status codes, headers, JSON or literal text/binary
bodies, and the five explicit NaughtyStrings generators. The numbered profiles
provide synthetic config files and common web-service decoys. Arbitrary C#
scripts, callbacks, and legacy
`Mocks` templates are not supported.

Settings can be mounted at `/app/Settings` or overridden with environment
variables such as `Recon__Workers` and `Honeypot__UnmatchedStatusCode`.

See the [repository README](../../../README.md) for the profile format, SQL
deployment, recon behavior, and integration checks.
