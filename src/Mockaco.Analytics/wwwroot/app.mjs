import { buildMatrix, filterSources, servicePage, NO_OBSERVATIONS } from "./model.mjs?v=3";
import { Constellation, familyColors } from "./constellation.mjs?v=3";

const $ = id => document.getElementById(id);
const number = value => Number(value).toLocaleString();
const date = value => value ? value.slice(0, 10) : "Not recorded";
const timestamp = value => value ? value.slice(0, 19).replace("T", " ") : "Not recorded";
const state = {
    snapshot: null, window: {}, filters: {}, matched: [], matrix: { rows: [], columns: [] },
    page: 0, servicePage: 0, cohort: [], cohortKey: null, cohortSnapshot: null,
    selectedId: null, neighbors: [], sourceController: null, snapshotController: null
};
const atlas = new Constellation($("constellation"), $("chart-tooltip"), node =>
    node.kind === "fingerprint" ? selectFingerprint(node.id) : selectSource(node.id));

function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}
function button(text, onClick, className = "") {
    const node = element("button", className, text);
    node.type = "button";
    node.addEventListener("click", onClick);
    return node;
}
function rememberFocus() {
    const key = document.activeElement?.dataset.focusKey;
    return () => {
        if (key) document.querySelector(`[data-focus-key="${CSS.escape(key)}"]`)?.focus({ preventScroll: true });
    };
}
function parameters(extra = {}) {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries({ ...state.window, ...extra }))
        if (value !== "" && value !== null && value !== undefined) query.set(key, value);
    return query;
}
async function api(path, extra, signal) {
    const response = await fetch(`${path}?${parameters(extra)}`, { signal });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
    return data;
}
function chartMessage(message, loading = false) {
    $("chart-message").hidden = !message;
    $("chart-message").replaceChildren();
    if (loading) $("chart-message").append(element("span", "loading-indicator"));
    if (message) $("chart-message").append(element("p", "", message));
}
async function loadSnapshot(refresh = false) {
    state.snapshotController?.abort();
    state.sourceController?.abort();
    const controller = state.snapshotController = new AbortController();
    const requestedWindow = { from: $("from").value, before: $("before").value };
    const changedWindow = JSON.stringify(state.window) !== JSON.stringify(requestedWindow);
    $("error").hidden = true;
    $("refresh").disabled = $("apply").disabled = true;
    $("filters").setAttribute("aria-busy", "true");
    chartMessage("Reading paths. Building the atlas.", true);
    try {
        const snapshot = await api("/api/snapshot", { ...requestedWindow, refresh }, controller.signal);
        if (controller.signal.aborted) return;
        state.sourceController?.abort();
        state.window = requestedWindow;
        state.snapshot = snapshot;
        state.page = 0;
        state.neighbors = [];
        if (changedWindow) state.filters.fingerprint = null;
        if (!snapshot.sources.some(source => source.hostId === state.selectedId)) state.selectedId = null;
        atlas.setData(snapshot.sources, changedWindow);
        $("capture-range").textContent = snapshot.firstSeen
            ? `${date(snapshot.firstSeen)} to ${date(snapshot.lastSeen)} / database clock` : "No requests in this date window";
        $("snapshot-time").textContent = `Snapshot loaded ${new Date(snapshot.loadedAt).toLocaleString()}`;
        $("projection-quality").textContent = `${(snapshot.explainedVariance * 100).toFixed(1)}% of profile variance retained in 2D`;
        chartMessage(snapshot.sources.length ? "" : "No captured sources in this date window. Try All time.");
        applyFilters();
        if (state.selectedId) await selectSource(state.selectedId, false);
        else renderOverview();
    } catch (error) {
        if (error.name !== "AbortError" && !controller.signal.aborted) {
            $("error").textContent = `${error.message}${state.snapshot ? " The previous snapshot is still displayed." : ""}`;
            $("error").hidden = false;
            chartMessage(state.snapshot ? "" : "The atlas could not be loaded. Check the error above, then Refresh data.");
        }
    } finally {
        if (state.snapshotController === controller) {
            $("refresh").disabled = $("apply").disabled = false;
            $("filters").setAttribute("aria-busy", "false");
        }
    }
}

function applyFilters(resetPage = true) {
    if (!state.snapshot) return;
    state.filters.query = $("search").value;
    state.filters.minimum = Math.max(1, Number($("minimum").value) || 1);
    const cohortKey = JSON.stringify([state.filters.query, state.filters.minimum, state.filters.fingerprint]);
    if (state.cohortSnapshot !== state.snapshot || state.cohortKey !== cohortKey) {
        state.cohort = filterSources(state.snapshot.sources, { ...state.filters, family: null, service: null });
        state.matrix = buildMatrix(state.cohort);
        state.cohortSnapshot = state.snapshot;
        state.cohortKey = cohortKey;
        state.servicePage = 0;
    }
    state.matched = filterSources(state.cohort, { family: state.filters.family, service: state.filters.service })
        .sort((a, b) => b.requests - a.requests || a.hostId - b.hostId);
    if (resetPage) state.page = 0;
    if (state.selectedId && !state.matched.some(source => source.hostId === state.selectedId)) {
        state.sourceController?.abort();
        state.selectedId = null;
        state.neighbors = [];
        renderOverview();
    }
    $("scope-summary").replaceChildren(
        element("strong", "", number(state.matched.length)),
        document.createTextNode(` of ${number(state.snapshot.sources.length)} sources / `),
        element("strong", "", number(state.matched.reduce((sum, source) => sum + source.requests, 0))),
        document.createTextNode(" matching requests"));
    if (state.snapshot.unattributedRequests)
        $("scope-summary").append(document.createTextNode(` / ${number(state.snapshot.unattributedRequests)} requests have no linked source`));
    $("selection-label").textContent = [
        state.filters.fingerprint ? "Shared fingerprint" : null,
        state.filters.family, state.filters.service === NO_OBSERVATIONS ? "No service observations" : state.filters.service
    ].filter(Boolean).join(" / ") || "All behaviors / all services";
    $("clear-selection").hidden = !state.filters.fingerprint && !state.filters.family && !state.filters.service;
    atlas.setSelection(state.matched, state.selectedId, state.neighbors);
    renderLegend();
    renderMatrix();
    renderSources();
}

function renderLegend() {
    const restoreFocus = rememberFocus();
    $("legend").replaceChildren();
    const families = [...new Set(state.snapshot.sources.flatMap(source => source.families))];
    for (const family of Object.keys(familyColors).filter(name => families.includes(name))) {
        const control = button("", () => {
            state.filters.family = state.filters.family === family ? null : family;
            applyFilters();
        });
        control.style.setProperty("--family", familyColors[family]);
        control.append(element("span", "swatch"), document.createTextNode(family));
        control.setAttribute("aria-pressed", String(state.filters.family === family));
        control.dataset.focusKey = `legend:${family}`;
        $("legend").append(control);
    }
    restoreFocus();
}

function renderMatrix() {
    const restoreFocus = rememberFocus();
    const { rows, columns } = state.matrix;
    const page = servicePage(columns, $("service-search").value, state.servicePage);
    const visibleColumns = page.items;
    state.servicePage = page.page;
    $("matrix-summary").textContent = page.total
        ? `Services ${number(page.start)}-${number(page.end)} of ${number(page.total)}${page.total !== columns.length ? ` matching / ${number(columns.length)} total` : ""}`
        : `No matching services / ${number(columns.length)} total`;
    $("previous-services").disabled = page.page === 0;
    $("next-services").disabled = page.page >= page.pages - 1;
    const pagePicker = $("service-page");
    if (pagePicker.options.length !== page.pages) {
        pagePicker.replaceChildren(...Array.from({ length: page.pages }, (_, index) => {
            const option = element("option", "", `Page ${number(index + 1)} of ${number(page.pages)}`);
            option.value = index;
            return option;
        }));
    }
    pagePicker.value = page.page;
    pagePicker.disabled = page.pages === 1;
    const table = $("matrix");
    table.replaceChildren(element("caption", "sr-only", "Distinct sources by requested family and observed service"));
    if (!rows.length || !visibleColumns.length) {
        const tbody = element("tbody"), tr = element("tr");
        tr.append(element("td", "matrix-empty", rows.length ? "No service names match this search." : "No sources match this cohort."));
        tbody.append(tr); table.append(tbody); return;
    }
    const header = element("thead"), headerRow = element("tr");
    headerRow.append(element("th", "", "Requested here"));
    for (const column of visibleColumns) {
        const th = element("th");
        th.scope = "col";
        const label = column.service === NO_OBSERVATIONS ? "No observations" : column.service;
        const control = button(label, () => {
            state.filters.service = state.filters.service === column.service ? null : column.service;
            applyFilters();
        });
        control.className = "service-heading";
        control.dataset.focusKey = `service:${column.service}`;
        control.setAttribute("aria-pressed", String(state.filters.service === column.service));
        control.setAttribute("aria-label", `${label}: ${number(column.total)} sources. Filter by this service.`);
        th.append(control, element("small", "", number(column.total)));
        headerRow.append(th);
    }
    header.append(headerRow);
    const body = element("tbody");
    const percent = $("matrix-mode").value === "percent";
    const largest = Math.max(1, ...rows.flatMap(row => [...row.cells.values()]));
    for (const row of rows) {
        const tr = element("tr"), heading = element("th");
        heading.scope = "row";
        const rowControl = button("", () => {
            state.filters.family = state.filters.family === row.family ? null : row.family;
            applyFilters();
        });
        rowControl.append(document.createTextNode(row.family), element("small", "", `${number(row.total)} sources`));
        rowControl.setAttribute("aria-pressed", String(state.filters.family === row.family));
        rowControl.dataset.focusKey = `row:${row.family}`;
        heading.append(rowControl); tr.append(heading);
        for (const column of visibleColumns) {
            const value = row.cells.get(column.service) || 0;
            const ratio = value / row.total;
            const selected = state.filters.family === row.family && state.filters.service === column.service;
            const control = button(value ? (percent ? `${(ratio * 100).toFixed(1)}%` : number(value)) : "0", () => {
                state.filters.family = selected ? null : row.family;
                state.filters.service = selected ? null : column.service;
                applyFilters();
            }, `matrix-cell${value ? "" : " zero"}`);
            const description = `${row.family} / ${column.service}: ${number(value)} of ${number(row.total)} sources (${(ratio * 100).toFixed(1)}%)`;
            control.title = description;
            control.setAttribute("aria-label", description);
            control.setAttribute("aria-pressed", String(selected));
            control.dataset.family = row.family;
            control.dataset.service = column.service;
            control.dataset.count = value;
            control.dataset.focusKey = `cell:${JSON.stringify([row.family, column.service])}`;
            control.style.setProperty("--heat", `${value ? 20 + 80 * (percent ? ratio : Math.log1p(value) / Math.log1p(largest)) : 0}%`);
            const td = element("td"); td.append(control); tr.append(td);
        }
        body.append(tr);
    }
    table.append(header, body);
    restoreFocus();
}

function renderSources() {
    const restoreFocus = rememberFocus();
    const pageSize = 30;
    const pages = Math.max(1, Math.ceil(state.matched.length / pageSize));
    state.page = Math.min(state.page, pages - 1);
    $("source-count").textContent = `${number(state.matched.length)} sources`;
    $("source-rows").replaceChildren();
    for (const source of state.matched.slice(state.page * pageSize, (state.page + 1) * pageSize)) {
        const row = element("tr", source.hostId === state.selectedId ? "selected" : "");
        const address = element("td");
        const control = button(source.ipAddress, () => selectSource(source.hostId));
        control.dataset.hostId = source.hostId;
        control.dataset.focusKey = `source:${source.hostId}`;
        address.append(control);
        row.append(address, element("td", "numeric", number(source.requests)),
            element("td", "numeric", number(source.pathCount)),
            element("td", "", source.dominantFamily), element("td", "mono", date(source.lastSeen)));
        $("source-rows").append(row);
    }
    if (!state.matched.length) {
        const row = element("tr"), cell = element("td", "matrix-empty", "No sources match. Clear the selection or adjust the filters.");
        cell.colSpan = 5; row.append(cell); $("source-rows").append(row);
    }
    $("page-label").textContent = `Page ${state.page + 1} of ${number(pages)}`;
    $("previous-page").disabled = state.page === 0;
    $("next-page").disabled = state.page >= pages - 1;
    restoreFocus();
}

function selectFingerprint(id) {
    state.filters.fingerprint = state.filters.fingerprint === id ? null : id;
    state.filters.family = state.filters.service = null;
    state.selectedId = null;
    state.neighbors = [];
    state.sourceController?.abort();
    applyFilters();
    renderOverview();
}

function renderOverview() {
    $("close-source").hidden = true;
    const content = $("inspector-content");
    content.replaceChildren();
    const group = atlas.groups.find(item => item.id === state.filters.fingerprint);
    $("inspector-title").textContent = group ? "A shared fingerprint" : "Follow a fingerprint";
    if (group) {
        content.append(element("p", "muted", `${number(group.sources.length)} sources requested the same normalized route/method set. Similarity is not evidence of common ownership.`));
        content.append(element("p", "tag", group.label));
        content.append(button("Expand as individual sources", () => setView("sources"), "outline-action"));
        content.append(button("Inspect the busiest matching source", () => {
            if (state.matched[0]) selectSource(state.matched[0].hostId);
        }, "outline-action"));
    } else {
        content.append(element("p", "muted", "Nearby nodes have similar request profiles in this projection. Select a fingerprint to cross-filter the matrix, or select a source to inspect the evidence."));
        const section = element("section", "inspector-section");
        section.append(element("h3", "", "Most shared fingerprints"));
        for (const item of [...atlas.groups].sort((a, b) => b.sources.length - a.sources.length).slice(0, 6)) {
            const control = button("", () => selectFingerprint(item.id), "group-button");
            control.append(element("span", "", item.label), element("span", "", number(item.sources.length)));
            section.append(control);
        }
        content.append(section);
    }
    const hint = element("section", "inspector-section");
    hint.append(element("h3", "", "Read both sides"), element("p", "", "Matrix rows describe requests received by the honeypot. Columns describe services found on the sources that sent them. These are observations, not confirmed vulnerabilities."));
    content.append(hint);
}

function facts(source) {
    const list = element("dl", "fact-grid");
    for (const [label, value, small] of [
        ["Requests", number(source.requests)], ["Route / method pairs", number(source.pathCount)],
        ["First request", timestamp(source.firstSeen), true], ["Last request", timestamp(source.lastSeen), true]
    ]) {
        const item = element("div");
        item.append(element("dt", "", label), element("dd", small ? "small" : "", value));
        list.append(item);
    }
    return list;
}
function section(title, description) {
    const node = element("section", "inspector-section");
    node.append(element("h3", "", title));
    if (description) node.append(element("p", "", description));
    return node;
}

async function selectSource(id, scroll = true) {
    const source = state.snapshot?.sources.find(item => item.hostId === id);
    if (!source) return;
    state.sourceController?.abort();
    const controller = state.sourceController = new AbortController();
    state.selectedId = id;
    state.neighbors = [];
    $("inspector-title").textContent = source.ipAddress;
    $("close-source").hidden = false;
    const content = $("inspector-content");
    content.replaceChildren(element("span", "tag", `Host #${id}`), facts(source), element("p", "muted", "Loading captured evidence..."));
    atlas.setSelection(state.matched, id);
    renderSources();
    if (scroll && matchMedia("(max-width: 820px)").matches) $("inspector-title").scrollIntoView({ block: "start" });
    try {
        const [detail, neighbors] = await Promise.all([
            api(`/api/sources/${id}`, {}, controller.signal),
            api(`/api/sources/${id}/neighbors`, {}, controller.signal)
        ]);
        if (controller.signal.aborted || state.selectedId !== id) return;
        state.neighbors = neighbors;
        atlas.setSelection(state.matched, id, neighbors);
        content.replaceChildren(element("span", "tag", `Host #${id}`), facts(source));
        for (const hostname of detail.hostnames) content.append(element("span", "tag", hostname));
        content.append(button("Select this fingerprint's sources", () => selectFingerprint(source.fingerprint), "outline-action"));
        const similar = section("Closest behavioral matches", "Full-profile cosine similarity; not a confidence score for attribution.");
        if (!neighbors.length) similar.append(element("p", "", "No other sources share a normalized route/method pair in this date window."));
        for (const neighbor of neighbors) {
            const control = button("", () => {
                if (!state.matched.some(item => item.hostId === neighbor.hostId)) {
                    state.filters = {}; $("search").value = ""; $("minimum").value = "1"; applyFilters();
                }
                selectSource(neighbor.hostId);
            }, "neighbor-button");
            control.title = `Shared paths:\n${neighbor.sharedPaths.join("\n")}`;
            control.append(element("span", "", neighbor.ipAddress), element("span", "", `${(neighbor.similarity * 100).toFixed(1)}%`));
            similar.append(control);
        }
        content.append(similar);
        const paths = section("Requested paths", "Raw paths in the selected date window. Counts are not normalized.");
        const pathList = element("div", "detail-list");
        for (const path of detail.paths) {
            const row = element("div", "path-row");
            row.append(element("code", "", `${path.method} ${path.target || "(empty target)"}`), element("span", "", number(path.count)));
            pathList.append(row);
        }
        paths.append(pathList); content.append(paths);
        const services = section("Observed services", "Nmap scans and Shodan host records, across all dates. Shodan lookup time is not a new scan.");
        const serviceList = element("div", "detail-list");
        if (!detail.services.length) services.append(element("p", "", "No service observations were stored for this source."));
        for (const service of detail.services) {
            const item = element("details");
            const provenance = service.provider === "Shodan"
                ? `Shodan observed: ${service.observedAtUtc ? timestamp(service.observedAtUtc) : "not supplied"}\nRetrieved: ${timestamp(service.retrievedAtUtc)}`
                : `Job updated: ${timestamp(service.jobUpdatedAt)}`;
            item.append(element("summary", "", `Port ${service.portNumber ?? "not recorded"} / ${service.provider || "Nmap"} / job #${service.hostJobId}`),
                element("pre", "", `${service.detail || "(empty banner)"}\n\n${provenance}`));
            serviceList.append(item);
        }
        services.append(serviceList);
        for (const job of detail.jobs) {
            const names = { 0: "Pending", 1: "Completed", 2: "Running (recorded state)", 3: "Failed" };
            const item = element("details");
            const evidence = job.provider === "Shodan" && job.statusCode
                ? `\nShodan HTTP ${job.statusCode}${job.statusCode === 404 ? " (no host information)" : ""}\nRetrieved: ${timestamp(job.retrievedAtUtc)}` : "";
            item.append(element("summary", "", `${job.provider || "Nmap"} job #${job.hostJobId}: ${names[job.state] || `State ${job.state}`}`),
                element("pre", "", `Updated: ${timestamp(job.updatedAt)}${evidence}${job.lastError ? `\n${job.lastError}` : ""}`));
            serviceList.append(item);
        }
        content.append(services);
        const requests = section("Captured requests", "Newest request IDs first. Expand for target host, query string and timestamp.");
        const requestList = element("div", "detail-list");
        const more = button("Load older requests", async () => {
            more.disabled = true;
            try {
                const page = await api(`/api/sources/${id}`, { cursor: more.dataset.cursor }, controller.signal);
                if (controller.signal.aborted || state.selectedId !== id) return;
                appendRequests(requestList, page.requests);
                more.dataset.cursor = page.nextCursor || "";
                more.hidden = !page.nextCursor;
            } catch (error) {
                if (error.name !== "AbortError") requests.append(element("p", "inline-error", error.message));
            } finally { more.disabled = false; }
        }, "outline-action");
        appendRequests(requestList, detail.requests);
        more.dataset.cursor = detail.nextCursor || "";
        more.hidden = !detail.nextCursor;
        requests.append(requestList, more); content.append(requests);
    } catch (error) {
        if (error.name !== "AbortError") content.append(element("p", "inline-error", error.message));
    }
}

function appendRequests(container, requests) {
    for (const request of requests) {
        const item = element("details");
        item.append(element("summary", "", `#${request.requestId} ${request.method} ${request.target || "(empty target)"}`),
            element("pre", "", `Time: ${timestamp(request.createdDate)}\nHost: ${request.targetHost ?? "(not recorded)"}\nMethod: ${request.method}\nPath: ${request.target}\nQuery: ${request.queryString ?? ""}`));
        container.append(item);
    }
}
function setView(mode) {
    atlas.setMode(mode);
    $("view-groups").setAttribute("aria-pressed", String(mode === "groups"));
    $("view-sources").setAttribute("aria-pressed", String(mode === "sources"));
    $("view-description").textContent = mode === "groups"
        ? "One node per shared route/method set. Node size is log-scaled source count. Select a fingerprint to explore."
        : "One point per source IP. Point size is log-scaled request count. Select a source for its full-profile matches.";
}

$("filters").addEventListener("submit", event => { event.preventDefault(); loadSnapshot(); });
$("all-time").addEventListener("click", () => { $("from").value = $("before").value = ""; loadSnapshot(); });
$("refresh").addEventListener("click", () => loadSnapshot(true));
let searchTimer;
$("search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => applyFilters(), 120); });
$("minimum").addEventListener("input", () => applyFilters());
$("service-search").addEventListener("input", () => { state.servicePage = 0; renderMatrix(); });
$("matrix-mode").addEventListener("change", renderMatrix);
$("previous-services").addEventListener("click", () => changeServicePage(state.servicePage - 1));
$("next-services").addEventListener("click", () => changeServicePage(state.servicePage + 1));
$("service-page").addEventListener("change", () => changeServicePage(Number($("service-page").value)));
function changeServicePage(page) {
    state.servicePage = page;
    $("matrix-scroll").scrollLeft = 0;
    renderMatrix();
}
$("clear-selection").addEventListener("click", () => {
    state.filters.family = state.filters.service = state.filters.fingerprint = null;
    applyFilters();
    if (!state.selectedId) renderOverview();
});
$("close-source").addEventListener("click", () => {
    state.sourceController?.abort(); state.selectedId = null; state.neighbors = [];
    atlas.setSelection(state.matched, null); renderOverview(); renderSources();
});
$("view-groups").addEventListener("click", () => setView("groups"));
$("view-sources").addEventListener("click", () => setView("sources"));
$("spread").addEventListener("change", () => atlas.setSpread($("spread").checked));
$("zoom-in").addEventListener("click", () => atlas.scale(1.5));
$("zoom-out").addEventListener("click", () => atlas.scale(1 / 1.5));
$("reset-view").addEventListener("click", () => atlas.fit());
for (const [id, x, y] of [["pan-left", 80, 0], ["pan-right", -80, 0], ["pan-up", 0, 80], ["pan-down", 0, -80]])
    $(id).addEventListener("click", () => atlas.pan(x, y));
$("pan-menu").addEventListener("keydown", event => {
    if (event.key === "Escape") {
        $("pan-menu").open = false;
        $("pan-menu").querySelector("summary").focus();
    }
});
$("previous-page").addEventListener("click", () => { state.page--; renderSources(); });
$("next-page").addEventListener("click", () => { state.page++; renderSources(); });
export function showBehavior() {
    if (!state.snapshot) loadSnapshot();
}
export function invalidateBehavior() {
    state.snapshotController?.abort();
    state.sourceController?.abort();
    state.snapshot = null;
    state.selectedId = null;
    state.neighbors = [];
    if (!$("behavior-view").hidden) loadSnapshot();
}
