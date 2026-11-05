import { showBehavior, invalidateBehavior } from "./app.mjs?v=5";
import { summarizeEvidence, utcTimestamp, lookupState, latestEvidence } from "./intelligence-model.mjs?v=4";

const $ = id => document.getElementById(id);
const number = value => Number(value || 0).toLocaleString();
const databaseTime = value => value ? value.slice(0, 19).replace("T", " ") : "No captured requests";
const text = value => value === null || value === undefined || value === "" ? "Not reported"
    : typeof value === "object" ? JSON.stringify(value) : String(value);
const state = { collection: null, page: 0, controller: null, host: null, opener: null };
const cleanup = { hosts: null, busy: false, controller: null, visible: 50 };
const tabs = [["overview", "Overview"], ["services", "Services"], ["vulnerabilities", "CVEs"],
    ["traffic", "Traffic"], ["raw", "Raw evidence"]];

function node(tag, className = "", content) {
    const result = document.createElement(tag);
    if (className) result.className = className;
    if (content !== undefined) result.textContent = content;
    return result;
}
function action(label, handler, className = "") {
    const result = node("button", className, label);
    result.type = "button";
    result.addEventListener("click", handler);
    return result;
}
function badge(label, tone = "neutral") { return node("span", `evidence-badge ${tone}`, label); }
function empty(message) { return node("p", "empty-evidence", message); }
function note(message) { return node("p", "evidence-note", message); }
function heading(title, description) {
    const section = node("section", "dossier-section");
    section.append(node("h3", "", title));
    if (description) section.append(node("p", "section-description", description));
    return section;
}
function facts(values) {
    const list = node("dl", "evidence-facts");
    for (const [label, value] of values) {
        const item = node("div");
        item.append(node("dt", "", label), node("dd", "", text(value)));
        list.append(item);
    }
    return list;
}
function tags(values, fallback) {
    const list = node("div", "evidence-tags");
    for (const value of [...new Set((Array.isArray(values) ? values : []).map(String))])
        list.append(node("span", "tag", value));
    if (!list.childElementCount) list.append(node("p", "muted", fallback));
    return list;
}
async function request(path, signal, asText = false, options = {}) {
    const response = await fetch(path, { ...options, signal });
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || `Request failed (${response.status}).`);
    }
    return asText ? response.text() : response.json();
}

async function loadCollection(page = 0) {
    state.controller?.abort();
    const controller = state.controller = new AbortController();
    const query = new URLSearchParams({ query: $("intel-search").value, status: $("intel-state").value,
        sort: $("intel-sort").value, page });
    $("intel-error").hidden = true;
    $("intel-refresh").disabled = true;
    $("intel-previous").disabled = $("intel-next").disabled = true;
    $("intel-rows").closest("table").setAttribute("aria-busy", "true");
    $("intel-result").textContent = state.collection ? "Updating the collection..." : "Reading stored intelligence...";
    try {
        const collection = await request(`/api/intelligence?${query}`, controller.signal);
        if (controller.signal.aborted) return;
        state.collection = collection;
        state.page = collection.page;
        renderCollection(collection);
    } catch (error) {
        if (!controller.signal.aborted) {
            $("intel-error").textContent = `${error.message}${state.collection ? " Previous results remain visible." : " Try Refresh collection."}`;
            $("intel-error").hidden = false;
            $("intel-result").textContent = state.collection ? "Previous collection snapshot" : "Collection unavailable";
        }
    } finally {
        if (state.controller === controller) {
            $("intel-refresh").disabled = false;
            $("intel-rows").closest("table").setAttribute("aria-busy", "false");
        }
    }
}

function renderCollection(collection) {
    const s = collection.summary;
    $("intel-metrics").replaceChildren();
    for (const [label, value, description, tone] of [
        ["Source IPs", s.totalHosts, `${number(s.nmapCompleted)} with completed Nmap jobs`, ""],
        ["Captured requests", s.totalRequests, `${number(s.serviceObservations)} service observations`, ""],
        ["Shodan profiles", s.shodanAvailable, `${number(s.shodanNoData)} lookups returned no data`, "teal"],
        ["Hosts with reported CVEs", s.hostsWithCves, "Provider reports, not confirmed findings", "amber"]
    ]) {
        const card = node("div", `metric-card ${tone}`);
        card.append(node("span", "", label), node("strong", "", number(value)), node("small", "", description));
        $("intel-metrics").append(card);
    }
    renderRanks("intel-countries", collection.countries, "No country information has been stored yet.");
    renderRanks("intel-organizations", collection.organizations, "No organization information has been stored yet.");
    const coverage = $("intel-coverage");
    const lookedUp = s.shodanAvailable + s.shodanNoData;
    const percent = s.totalHosts ? lookedUp * 100 / s.totalHosts : 0;
    coverage.replaceChildren(node("p", "coverage-number", `${percent.toFixed(1)}%`),
        node("p", "muted", `${number(lookedUp)} of ${number(s.totalHosts)} hosts have stored lookups`));
    const progress = node("progress");
    progress.max = s.totalHosts || 1;
    progress.value = lookedUp;
    progress.setAttribute("aria-label", "Hosts with stored Shodan lookup results");
    coverage.append(progress);
    const status = node("div", "coverage-states");
    status.append(badge(`${number(s.shodanAvailable)} available`, "available"),
        badge(`${number(s.shodanNoData)} no data`), badge(`${number(Math.max(0, s.totalHosts - lookedUp))} without results`));
    coverage.append(status, note(`Recorded queue: ${number(s.shodanPending)} pending / ${number(s.shodanRunning)} running / ${number(s.shodanFailed)} failed.`));
    const rows = $("intel-rows");
    rows.replaceChildren();
    for (const host of collection.hosts) {
        const row = node("tr");
        const address = node("td");
        const open = action(host.ipAddress, () => openHost(host.hostId, true), "host-link");
        open.dataset.hostId = host.hostId;
        open.setAttribute("aria-label", `Open dossier for ${host.ipAddress}`);
        address.append(open, node("small", "", `Host #${host.hostId}`));
        const network = node("td", "network-cell");
        network.append(node("span", "", host.organization || "Organization not reported"),
            node("small", "", [host.asn, host.country].filter(Boolean).join(" / ") || "No location or ASN reported"));
        const cves = node("td", "numeric");
        cves.append(host.cveCount ? badge(number(host.cveCount), "warning") : node("span", "muted", "0"));
        const lookup = node("td");
        const current = lookupState(host);
        lookup.append(badge(current.label, current.tone));
        row.append(address, network, node("td", "numeric", number(host.requests)),
            node("td", "numeric", number(host.portCount)), cves, lookup,
            node("td", "inventory-date", host.lastSeen ? databaseTime(host.lastSeen) : "No requests"));
        rows.append(row);
    }
    if (!collection.hosts.length) {
        const row = node("tr"), cell = node("td", "matrix-empty", "No hosts match these filters. Try another term or Clear filters.");
        cell.colSpan = 7; row.append(cell); rows.append(row);
    }
    const start = collection.total ? collection.page * collection.pageSize + 1 : 0;
    const end = Math.min((collection.page + 1) * collection.pageSize, collection.total);
    const pages = Math.max(1, Math.ceil(collection.total / collection.pageSize));
    $("intel-result").textContent = `${number(start)}-${number(end)} of ${number(collection.total)} matching hosts`;
    $("intel-page").textContent = `Page ${number(collection.page + 1)} of ${number(pages)}`;
    $("intel-previous").disabled = collection.page === 0;
    $("intel-next").disabled = collection.page >= pages - 1;
    $("snapshot-time").textContent = `Collection read ${utcTimestamp(collection.loadedAt)}`;
}

function renderRanks(id, items, fallback) {
    const list = $(id);
    list.replaceChildren();
    const maximum = Math.max(1, ...items.map(item => item.hosts));
    for (const item of items) {
        const control = action("", () => {
            $("intel-search").value = item.name;
            $("intel-state").value = "all";
            loadCollection();
            $("inventory-title").scrollIntoView({ block: "start" });
        }, "rank-row");
        control.append(node("span", "rank-name", item.name), node("span", "mono", number(item.hosts)));
        control.style.setProperty("--rank", `${item.hosts * 100 / maximum}%`);
        control.setAttribute("aria-label", `${item.name}: ${number(item.hosts)} hosts. Filter the collection.`);
        list.append(control);
    }
    if (!items.length) list.append(empty(fallback));
}

function switchView(view, update = true) {
    const behavior = view === "behavior";
    $("intelligence-view").hidden = behavior;
    $("behavior-view").hidden = !behavior;
    for (const name of ["intelligence", "behavior"]) {
        const selected = (name === "behavior") === behavior;
        $(`${name}-tab`).setAttribute("aria-selected", String(selected));
        $(`${name}-tab`).tabIndex = selected ? 0 : -1;
    }
    if (update) {
        const url = new URL(location.href);
        url.searchParams.set("view", behavior ? "behavior" : "intelligence");
        history.replaceState(history.state, "", url);
    }
    if (behavior) showBehavior();
    else {
        $("capture-range").textContent = "All-time capture / stored host intelligence";
        if (!state.collection && !state.controller) loadCollection();
    }
}

async function openHost(id, push = false) {
    state.host?.controller.abort();
    const host = { id, controller: new AbortController(), raw: null, rawCache: new Map(), detail: null,
        summary: summarizeEvidence(null), active: new URL(location.href).searchParams.get("panel") || "overview" };
    if (!tabs.some(([key]) => key === host.active)) host.active = "overview";
    state.host = host;
    if (push) {
        const url = new URL(location.href);
        url.searchParams.set("host", id);
        url.searchParams.delete("panel");
        host.active = "overview";
        history.pushState({ atlasHost: true }, "", url);
    }
    $("host-title").textContent = `Host #${id}`;
    $("host-subtitle").textContent = "Loading stored evidence...";
    $("host-tabs").replaceChildren();
    $("host-body").replaceChildren();
    for (const [key, label] of tabs) {
        const control = action(label, () => selectHostTab(key), "dossier-tab");
        control.id = `host-tab-${key}`;
        control.setAttribute("role", "tab");
        control.setAttribute("aria-controls", `host-panel-${key}`);
        control.setAttribute("aria-selected", String(key === host.active));
        control.tabIndex = key === host.active ? 0 : -1;
        control.disabled = true;
        $("host-tabs").append(control);
        const panel = node("section", "dossier-panel");
        panel.id = `host-panel-${key}`;
        panel.setAttribute("role", "tabpanel");
        panel.setAttribute("aria-labelledby", control.id);
        panel.hidden = key !== host.active;
        panel.append(note("Loading stored evidence..."));
        $("host-body").append(panel);
    }
    if (!$("host-dialog").open) {
        state.opener = document.activeElement;
        $("host-dialog").showModal();
        document.body.classList.add("dossier-open");
    }
    try {
        host.detail = await request(`/api/sources/${id}`, host.controller.signal);
        if (state.host !== host) return;
        host.evidence = latestEvidence(host.detail.jobs);
        if (host.evidence) {
            try {
                const raw = await request(`/api/sources/${id}/evidence/${host.evidence.hostJobId}`, host.controller.signal, true);
                host.rawCache.set(host.evidence.hostJobId, raw);
                host.raw = JSON.parse(raw);
                host.summary = summarizeEvidence(host.raw);
            } catch (error) {
                if (host.controller.signal.aborted) return;
                host.evidenceError = `Shodan detail could not be decoded: ${error.message}`;
            }
        }
        if (state.host !== host || host.controller.signal.aborted) return;
        $("host-title").textContent = host.detail.ipAddress;
        $("host-subtitle").textContent = [host.raw?.org, host.raw?.city, host.raw?.country_name].filter(Boolean).join(" / ")
            || `Host #${id} / recorded source evidence`;
        for (const control of $("host-tabs").children) control.disabled = false;
        selectHostTab(host.active, false);
    } catch (error) {
        if (host.controller.signal.aborted) return;
        $("host-subtitle").textContent = "Evidence unavailable";
        const panel = $(`host-panel-${host.active}`);
        panel.replaceChildren(node("p", "inline-error", error.message),
            action("Retry loading", () => openHost(id), "outline-action"));
    }
}

function selectHostTab(key, update = true) {
    const host = state.host;
    if (!host?.detail) return;
    host.active = key;
    for (const [name] of tabs) {
        const selected = name === key;
        $(`host-tab-${name}`).setAttribute("aria-selected", String(selected));
        $(`host-tab-${name}`).tabIndex = selected ? 0 : -1;
        $(`host-panel-${name}`).hidden = !selected;
    }
    const panel = $(`host-panel-${key}`);
    if (!panel.dataset.rendered) {
        panel.replaceChildren();
        ({ overview: renderHostOverview, services: renderHostServices, vulnerabilities: renderVulnerabilities,
            traffic: renderTraffic, raw: renderRaw })[key](panel, host);
        panel.dataset.rendered = "true";
    }
    $("host-body").scrollTop = 0;
    if (update) {
        const url = new URL(location.href);
        url.searchParams.set("panel", key);
        history.replaceState(history.state, "", url);
    }
}

function renderHostOverview(panel, host) {
    const raw = host.raw || {};
    const current = lookupState({ statusCode: host.evidence?.statusCode,
        shodanState: host.detail.jobs.find(job => job.provider === "Shodan")?.state });
    const summary = node("div", "dossier-summary");
    summary.append(badge(`Shodan: ${current.label}`, current.tone),
        badge(`${number(host.detail.services.length)} service records`),
        badge(`${number(host.summary.vulnerabilities.length)} reported CVEs`, host.summary.vulnerabilities.length ? "warning" : "neutral"));
    panel.append(summary);
    if (host.evidenceError) panel.append(node("p", "inline-error", host.evidenceError));
    if (host.evidence?.statusCode === 404)
        panel.append(note("Shodan returned no information for this IP at lookup time. This does not mean the host has no open services."));
    else if (!host.evidence)
        panel.append(note("No Shodan response has been stored for this host yet. Captured requests and Nmap records remain available in the other sections."));
    const network = heading("Network & geography", "Provider-reported context; location describes an IP record, not a person.");
    network.append(facts([["Organization", raw.org], ["ISP", raw.isp], ["ASN", raw.asn],
        ["Country", raw.country_name], ["City / region", [raw.city, raw.region_code].filter(Boolean).join(" / ")],
        ["Coordinates", raw.latitude != null && raw.longitude != null ? `${raw.latitude}, ${raw.longitude}` : null],
        ["Operating system", raw.os], ["Shodan last observed", utcTimestamp(raw.last_update)],
        ["Retrieved", utcTimestamp(host.evidence?.retrievedAtUtc)]]));
    panel.append(network);
    for (const [title, values, fallback] of [
        ["Hostnames", [...host.detail.hostnames, ...(Array.isArray(raw.hostnames) ? raw.hostnames : [])], "No hostnames recorded."],
        ["Domains", raw.domains, "No domains reported."], ["Tags", raw.tags, "No tags reported."]
    ]) {
        const section = heading(title);
        section.append(tags(values, fallback));
        panel.append(section);
    }
    const jobs = heading("Recon activity", "Stored job states, not a live process monitor. Times below use the database clock unless marked UTC.");
    for (const job of host.detail.jobs) {
        const item = node("details", "job-record");
        const names = { 0: "Pending", 1: "Completed", 2: "Running (recorded state)", 3: "Failed" };
        const title = node("summary");
        title.append(node("span", "", `${job.provider} / job #${job.hostJobId}`), badge(names[job.state] || `State ${job.state}`, job.state === 3 ? "warning" : "neutral"));
        item.append(title, facts([["Job updated", databaseTime(job.updatedAt)],
            ["HTTP result", job.statusCode ? `${job.statusCode}${job.statusCode === 404 ? " / no host information" : ""}` : null],
            ["Evidence retrieved", job.retrievedAtUtc ? utcTimestamp(job.retrievedAtUtc) : null]]));
        if (job.lastError) item.append(node("pre", "evidence-pre", job.lastError));
        jobs.append(item);
    }
    if (!host.detail.jobs.length) jobs.append(empty("No recon jobs recorded."));
    panel.append(jobs);
}

function disclosure(title, value) {
    const detail = node("details", "json-disclosure");
    detail.append(node("summary", "", title));
    detail.addEventListener("toggle", () => {
        if (detail.open && !detail.querySelector("pre"))
            detail.append(node("pre", "evidence-pre", typeof value === "string" ? value : JSON.stringify(value, null, 2)));
    });
    return detail;
}

function renderHostServices(panel, host) {
    panel.append(note("Nmap observations and Shodan service records. Shodan observation time is separate from retrieval time; lookup does not perform a new scan."));
    const controls = node("div", "evidence-controls");
    const searchLabel = node("label", "", "Find a service");
    const search = node("input"); search.type = "search"; search.placeholder = "Port, product, protocol or title";
    searchLabel.append(search);
    const providerLabel = node("label", "", "Provider");
    const provider = node("select");
    for (const name of ["All", "Shodan", "Nmap"]) {
        const option = node("option", "", name); option.value = name; provider.append(option);
    }
    providerLabel.append(provider); controls.append(searchLabel, providerLabel); panel.append(controls);
    const status = node("p", "result-description"); status.setAttribute("role", "status");
    const list = node("div", "service-grid");
    const records = [
        ...host.summary.services.map(service => ({ provider: "Shodan", port: service.port, protocol: service.transport, raw: service })),
        ...host.detail.services.filter(service => service.provider !== "Shodan" || service.hostJobId !== host.evidence?.hostJobId || !host.raw)
            .map(service => ({ provider: service.provider, port: service.portNumber, protocol: service.detail.split(/\s+/)[0], stored: service }))
    ].sort((a, b) => a.port - b.port || a.provider.localeCompare(b.provider));
    let visible = 50;
    const more = action("Show more service records", () => { visible += 50; render(); }, "outline-action");
    const render = () => {
        const query = search.value.toLowerCase();
        const matches = records.filter(record => (provider.value === "All" || record.provider === provider.value)
            && [record.port, record.protocol, record.raw?.product, record.raw?.version, record.raw?._shodan?.module,
                record.raw?.http?.title, record.stored?.detail].filter(value => value != null).join(" ").toLowerCase().includes(query));
        list.replaceChildren();
        for (const record of matches.slice(0, visible)) list.append(serviceCard(record, host));
        if (!matches.length) list.append(empty("No service records match. A missing observation is not evidence that a port is closed."));
        status.textContent = `${number(Math.min(matches.length, visible))} of ${number(matches.length)} matching service records`;
        more.hidden = visible >= matches.length;
    };
    search.addEventListener("input", () => { visible = 50; render(); });
    provider.addEventListener("change", () => { visible = 50; render(); });
    panel.append(status, list, more); render();
}

function serviceCard(record, host) {
    const service = record.raw;
    const card = node("details", "service-card");
    const summary = node("summary");
    const identity = node("span", "service-identity");
    identity.append(node("strong", "mono", `${record.port ?? "?"}/${record.protocol || "unknown"}`),
        node("span", "", service ? [service.product || service._shodan?.module || "Unidentified service", service.version].filter(Boolean).join(" ")
            : record.stored.detail.split("\n")[0]));
    summary.append(identity, badge(record.provider, record.provider === "Shodan" ? "available" : "neutral"));
    card.append(summary);
    card.addEventListener("toggle", () => {
        if (!card.open || card.dataset.loaded) return;
        card.dataset.loaded = "true";
        const body = node("div", "service-body");
        if (service) {
            body.append(facts([["Observed", utcTimestamp(service.timestamp)], ["Retrieved", utcTimestamp(host.evidence?.retrievedAtUtc)],
                ["Module", service._shodan?.module], ["Product", service.product], ["Version", service.version], ["Operating system", service.os]]));
            if (service.http) {
                const http = heading("HTTP");
                http.append(facts([["Title", service.http.title], ["Server", service.http.server],
                    ["Status", service.http.status], ["Host", service.http.host]]));
                if (service.http.components) http.append(tags(Object.keys(service.http.components), ""));
                body.append(http);
            }
            if (service.ssl) {
                const ssl = heading("TLS certificate");
                ssl.append(facts([["Subject", service.ssl.cert?.subject?.CN], ["Issuer", service.ssl.cert?.issuer?.CN || service.ssl.cert?.issuer?.O],
                    ["Issued (provider format)", service.ssl.cert?.issued], ["Expires (provider format)", service.ssl.cert?.expires],
                    ["Cipher", service.ssl.cipher?.name], ["Protocol", service.ssl.cipher?.version]]));
                body.append(ssl);
            }
            if (service.ssh) body.append(facts([["SSH fingerprint", service.ssh.fingerprint], ["SSH type", service.ssh.type]]));
            if (service.cpe || service.cpe23) body.append(tags([...(service.cpe || []), ...(service.cpe23 || [])], ""));
            if (service.data) body.append(disclosure("Full service banner", service.data));
            body.append(disclosure("All original service fields", service));
        } else {
            body.append(facts([["Job", record.stored.hostJobId],
                ["Observed", record.stored.observedAtUtc ? utcTimestamp(record.stored.observedAtUtc) : "Not recorded separately"],
                ["Job updated (database clock)", databaseTime(record.stored.jobUpdatedAt)]]),
                node("pre", "evidence-pre", record.stored.detail));
        }
        card.append(body);
    });
    return card;
}

function renderVulnerabilities(panel, host) {
    panel.append(note("These are Shodan-reported CVE associations, not independently confirmed vulnerabilities. Provider verification flags and CVSS scores are shown only when supplied."));
    const controls = node("div", "evidence-controls");
    const label = node("label", "", "Find a reported CVE");
    const search = node("input"); search.type = "search"; search.placeholder = "CVE identifier, port or description"; label.append(search);
    const scoreLabel = node("label", "", "Reported score");
    const severity = node("select");
    for (const [value, name] of [["all", "All scores"], ["high", "7.0 or above"], ["medium", "4.0-6.9"], ["low", "Below 4.0"], ["unknown", "Not supplied"]]) {
        const option = node("option", "", name); option.value = value; severity.append(option);
    }
    scoreLabel.append(severity); controls.append(label, scoreLabel);
    const count = node("p", "result-description"); count.setAttribute("role", "status");
    const list = node("div", "cve-list");
    let visible = 50;
    const more = action("Show more reported CVEs", () => { visible += 50; render(); }, "outline-action");
    const render = () => {
        const query = search.value.toLowerCase();
        const matches = host.summary.vulnerabilities.filter(item =>
            [item.id, item.summary, ...item.ports].join(" ").toLowerCase().includes(query)
            && (severity.value === "all" || (severity.value === "unknown" ? item.score === null
                : item.score !== null && (severity.value === "high" ? item.score >= 7
                    : severity.value === "medium" ? item.score >= 4 && item.score < 7 : item.score < 4))));
        list.replaceChildren();
        for (const item of matches.slice(0, visible)) {
            const row = node("details", "cve-record");
            const title = node("summary");
            title.append(node("strong", "mono", item.id), badge(item.score === null ? "No score" : `CVSS ${item.score.toFixed(1)}`,
                item.score >= 7 ? "warning" : "neutral"));
            row.append(title, node("p", "", item.summary || "No description was included in this response."),
                facts([["Service associations", item.ports.length ? item.ports.join(", ") : "Host-level report; port not supplied"],
                    ["Provider verification", item.verified === null ? "Not supplied" : item.verified ? "Flagged verified by Shodan" : "Not verified by Shodan"]]));
            list.append(row);
        }
        if (!matches.length) list.append(empty(host.summary.vulnerabilities.length
            ? "No reported CVEs match these filters." : "No CVE associations were included in the stored Shodan response. This is not a vulnerability assessment."));
        count.textContent = `${number(Math.min(visible, matches.length))} of ${number(matches.length)} reported CVEs`;
        more.hidden = visible >= matches.length;
    };
    search.addEventListener("input", () => { visible = 50; render(); });
    severity.addEventListener("change", () => { visible = 50; render(); });
    panel.append(controls, count, list, more); render();
}

function renderTraffic(panel, host) {
    const paths = host.detail.paths;
    panel.append(note(`${number(paths.reduce((sum, path) => sum + path.count, 0))} captured requests across ${number(paths.length)} method/path pairs. Timestamps use the database clock. This view does not replay traffic.`));
    const requests = heading("Captured requests", "Newest request IDs first. Expand a record for the original target host, query string and timestamp.");
    const list = node("div", "request-records");
    const append = records => {
        for (const record of records) {
            const row = node("details", "request-record");
            row.append(node("summary", "", `#${record.requestId} ${record.method} ${record.target || "(empty target)"}`),
                node("pre", "evidence-pre", `Time: ${databaseTime(record.createdDate)}\nHost: ${record.targetHost ?? "(not recorded)"}\nMethod: ${record.method}\nPath: ${record.target}\nQuery: ${record.queryString ?? ""}`));
            list.append(row);
        }
    };
    append(host.detail.requests);
    if (!host.detail.requests.length) list.append(empty("No HTTP requests are linked to this host."));
    let cursor = host.detail.nextCursor;
    const more = action("Load older requests", async () => {
        more.disabled = true;
        error.hidden = true;
        try {
            const page = await request(`/api/sources/${host.id}/requests?cursor=${cursor}`, host.controller.signal);
            if (state.host !== host) return;
            append(page.requests); cursor = page.nextCursor; more.hidden = !cursor;
        } catch (failure) {
            if (!host.controller.signal.aborted) { error.textContent = failure.message; error.hidden = false; }
        } finally { more.disabled = false; }
    }, "outline-action");
    more.hidden = !cursor;
    const error = node("p", "inline-error"); error.setAttribute("role", "alert"); error.hidden = true;
    requests.append(list, error, more); panel.append(requests);
    const routes = heading("Requested paths", "Case-preserving raw paths, grouped by method and path.");
    const routeList = node("div");
    let visible = 50;
    const addPaths = () => {
        routeList.replaceChildren();
        for (const path of paths.slice(0, visible)) {
            const row = node("div", "path-row");
            row.append(node("code", "", `${path.method} ${path.target || "(empty target)"}`), node("span", "", number(path.count)));
            routeList.append(row);
        }
        showMore.hidden = visible >= paths.length;
    };
    const showMore = action("Show more paths", () => { visible += 50; addPaths(); }, "outline-action");
    addPaths(); routes.append(routeList, showMore); panel.append(routes);
}

function renderRaw(panel, host) {
    panel.append(note("Complete stored responses, without removing fields. Load a response to inspect every returned field or download the original JSON. Large responses are loaded only when requested."));
    const jobs = host.detail.jobs.filter(job => job.statusCode && job.retrievedAtUtc);
    if (!jobs.length) { panel.append(empty("No raw API responses have been stored for this host.")); return; }
    const controls = node("div", "evidence-controls raw-controls");
    const label = node("label", "", "Stored response");
    const picker = node("select");
    for (const job of jobs) {
        const option = node("option", "", `Job #${job.hostJobId} / HTTP ${job.statusCode} / ${utcTimestamp(job.retrievedAtUtc)}`);
        option.value = job.hostJobId; picker.append(option);
    }
    label.append(picker);
    const output = node("pre", "evidence-pre raw-json");
    output.tabIndex = 0; output.setAttribute("aria-label", "Full stored JSON response"); output.hidden = true;
    const error = node("p", "inline-error"); error.setAttribute("role", "alert"); error.hidden = true;
    const download = node("a", "download-link", "Download JSON");
    const updateDownload = () => {
        download.href = `/api/sources/${host.id}/evidence/${picker.value}?download=true`;
        output.hidden = true;
    };
    const load = action("View JSON", async () => {
        load.disabled = true; error.hidden = true; picker.disabled = true;
        const jobId = Number(picker.value);
        try {
            let raw = host.rawCache.get(jobId);
            if (raw === undefined) {
                raw = await request(`/api/sources/${host.id}/evidence/${jobId}`, host.controller.signal, true);
                host.rawCache.set(jobId, raw);
            }
            if (state.host !== host) return;
            try { output.textContent = JSON.stringify(JSON.parse(raw), null, 2); }
            catch { output.textContent = raw; }
            output.hidden = false;
        } catch (failure) {
            if (!host.controller.signal.aborted) { error.textContent = failure.message; error.hidden = false; }
        } finally { load.disabled = false; picker.disabled = false; }
    });
    picker.addEventListener("change", updateDownload);
    updateDownload(); controls.append(label, load, download);
    panel.append(controls, error, output);
}

function closeHost(update = true) {
    state.host?.controller.abort();
    state.host = null;
    $("host-dialog").close();
    document.body.classList.remove("dossier-open");
    if (state.opener?.isConnected) state.opener.focus({ preventScroll: true });
    if (update) {
        if (history.state?.atlasHost) history.back();
        else {
            const url = new URL(location.href);
            url.searchParams.delete("host"); url.searchParams.delete("panel");
            history.replaceState(null, "", url);
        }
    }
}
function restoreLocation() {
    const url = new URL(location.href);
    switchView(url.searchParams.get("view"), false);
    const id = Number(url.searchParams.get("host"));
    if (Number.isSafeInteger(id) && id > 0) {
        if (state.host?.id !== id) openHost(id);
        else selectHostTab(tabs.some(([key]) => key === url.searchParams.get("panel")) ? url.searchParams.get("panel") : "overview", false);
    } else if (state.host) closeHost(false);
}
function tabKeyboard(event, controls) {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    const current = controls.indexOf(document.activeElement);
    if (current < 0) return;
    event.preventDefault();
    const index = event.key === "Home" ? 0 : event.key === "End" ? controls.length - 1
        : (current + (event.key === "ArrowRight" ? 1 : -1) + controls.length) % controls.length;
    controls[index].focus(); controls[index].click();
}

function renderCleanupHosts() {
    const rows = $("cleanup-rows");
    rows.replaceChildren();
    for (const host of (cleanup.hosts || []).slice(0, cleanup.visible)) {
        const row = node("tr");
        row.append(node("td", "mono", host.ipAddress), node("td", "", host.reason));
        rows.append(row);
    }
    if (cleanup.hosts && !cleanup.hosts.length) {
        const row = node("tr"), cell = node("td", "empty-evidence", "No non-public hosts in this selection.");
        cell.colSpan = 2; row.append(cell); rows.append(row);
    }
    $("cleanup-more").hidden = !cleanup.hosts || cleanup.visible >= cleanup.hosts.length;
}

function renderCleanupCounts(counts) {
    $("cleanup-counts").replaceChildren(facts([
        ["Hosts", number(counts.hosts)], ["Requests", number(counts.requests)], ["Headers", number(counts.headers)],
        ["Recon jobs", number(counts.jobs)], ["Service observations", number(counts.discoveries)],
        ["Hostnames", number(counts.hostnames)], ["Raw responses", number(counts.evidence)]
    ]));
}

async function loadCleanupPreview() {
    if (cleanup.busy) return;
    cleanup.controller?.abort();
    const controller = cleanup.controller = new AbortController();
    cleanup.hosts = null; cleanup.visible = 50;
    $("cleanup-purge").disabled = $("cleanup-refresh").disabled = true;
    $("cleanup-purge").textContent = "Purge hosts and linked data";
    $("cleanup-error").hidden = true;
    $("cleanup-counts").replaceChildren();
    $("cleanup-status").textContent = "Finding non-public hosts and counting linked records...";
    renderCleanupHosts();
    try {
        const preview = await request("/api/intelligence/non-public-hosts", controller.signal);
        if (controller.signal.aborted) return;
        cleanup.hosts = preview.hosts;
        renderCleanupCounts(preview.counts);
        renderCleanupHosts();
        $("cleanup-status").textContent = `${number(preview.hosts.length)} hosts selected for cleanup.`;
        $("cleanup-purge").textContent = `Purge ${number(preview.hosts.length)} hosts and linked data`;
        $("cleanup-purge").disabled = !preview.hosts.length;
    } catch (error) {
        if (!controller.signal.aborted) {
            $("cleanup-error").textContent = error.message;
            $("cleanup-error").hidden = false;
            $("cleanup-status").textContent = "Preview unavailable. Nothing has been deleted.";
        }
    } finally {
        if (cleanup.controller === controller) $("cleanup-refresh").disabled = false;
    }
}

async function purgeHosts() {
    if (cleanup.busy || !cleanup.hosts?.length) return;
    cleanup.busy = true;
    $("cleanup-purge").disabled = $("cleanup-refresh").disabled = true;
    $("cleanup-error").hidden = true;
    $("cleanup-status").textContent = "Purging the reviewed hosts and linked records...";
    try {
        const counts = await request("/api/intelligence/non-public-hosts/purge", undefined, false, {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ hostIds: cleanup.hosts.map(host => host.hostId) })
        });
        cleanup.hosts = [];
        renderCleanupHosts();
        renderCleanupCounts(counts);
        const result = `Purged ${number(counts.hosts)} hosts, ${number(counts.requests)} requests, ${number(counts.headers)} headers, ${number(counts.jobs)} recon jobs, ${number(counts.discoveries)} service observations, ${number(counts.hostnames)} hostnames and ${number(counts.evidence)} raw responses.`;
        $("cleanup-status").textContent = result;
        $("intel-maintenance-status").textContent = result;
        $("intel-maintenance-status").hidden = false;
        invalidateBehavior();
        await loadCollection();
    } catch (error) {
        $("cleanup-error").textContent = error.message;
        $("cleanup-error").hidden = false;
        $("cleanup-status").textContent = "Could not confirm the purge. Retry this selection or refresh the preview.";
    } finally {
        cleanup.busy = false;
        $("cleanup-refresh").disabled = false;
        $("cleanup-purge").disabled = !cleanup.hosts?.length;
    }
}

function closeCleanup() {
    if (!cleanup.busy) cleanup.controller?.abort();
    $("cleanup-dialog").close();
    document.body.classList.remove("cleanup-open");
    $("intel-cleanup").focus({ preventScroll: true });
}

$("intel-cleanup").addEventListener("click", () => {
    $("cleanup-dialog").showModal();
    document.body.classList.add("cleanup-open");
    if (!cleanup.busy) loadCleanupPreview();
});
$("cleanup-close").addEventListener("click", closeCleanup);
$("cleanup-dialog").addEventListener("cancel", event => { event.preventDefault(); closeCleanup(); });
$("cleanup-refresh").addEventListener("click", loadCleanupPreview);
$("cleanup-purge").addEventListener("click", purgeHosts);
$("cleanup-more").addEventListener("click", () => { cleanup.visible += 50; renderCleanupHosts(); });
$("intelligence-tab").addEventListener("click", () => switchView("intelligence"));
$("behavior-tab").addEventListener("click", () => switchView("behavior"));
document.querySelector(".workspace-tabs").addEventListener("keydown", event =>
    tabKeyboard(event, [$("intelligence-tab"), $("behavior-tab")]));
$("host-tabs").addEventListener("keydown", event =>
    tabKeyboard(event, [...$("host-tabs").children].filter(control => !control.disabled)));
$("host-close").addEventListener("click", () => closeHost());
$("host-dialog").addEventListener("cancel", event => { event.preventDefault(); closeHost(); });
window.addEventListener("popstate", restoreLocation);
$("intel-filters").addEventListener("submit", event => { event.preventDefault(); loadCollection(); });
let searchTimer;
$("intel-search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => loadCollection(), 250); });
for (const id of ["intel-state", "intel-sort"]) $(id).addEventListener("change", () => loadCollection());
$("intel-refresh").addEventListener("click", () => loadCollection(state.page));
$("intel-clear").addEventListener("click", () => {
    $("intel-search").value = ""; $("intel-state").value = "all"; $("intel-sort").value = "last-seen";
    loadCollection();
});
$("intel-previous").addEventListener("click", () => loadCollection(state.page - 1));
$("intel-next").addEventListener("click", () => loadCollection(state.page + 1));
restoreLocation();
