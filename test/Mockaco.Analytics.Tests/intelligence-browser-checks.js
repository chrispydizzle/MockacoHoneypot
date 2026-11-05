// Evaluate on a locally served atlas. All intelligence requests use offline fixtures.
(async () => {
    const $ = id => document.getElementById(id);
    const assert = (condition, message) => { if (!condition) throw new Error(message); };
    const waitFor = async predicate => {
        const deadline = Date.now() + 10000;
        while (!predicate()) {
            if (Date.now() > deadline) throw new Error("Timed out waiting for intelligence rendering.");
            await new Promise(resolve => setTimeout(resolve, 25));
        }
    };
    const change = (control, value, event = "change") => {
        control.value = value;
        control.dispatchEvent(new Event(event, { bubbles: true }));
    };
    const clickText = (root, label) => {
        const control = [...root.querySelectorAll("button")].find(button => button.textContent === label);
        assert(control, `Missing ${label} control.`); control.click();
    };
    const idle = () => !$("intel-refresh").disabled;
    const timestamp = "2026-10-30T12:00:00+00:00";
    const marker = '<img src="data:," onerror="window.__intelInjected=true">';
    const hosts = Array.from({ length: 51 }, (_, index) => ({
        hostId: index + 1, ipAddress: `192.0.2.${index + 1}`, requests: index ? 0 : 101,
        lastSeen: index ? null : timestamp, portCount: index ? 0 : 2,
        organization: index ? null : marker, country: index ? null : "Fixture country",
        asn: index ? null : "AS64500", cveCount: index ? 0 : 55,
        statusCode: index === 0 ? 200 : index === 1 ? 404 : null,
        shodanState: index < 2 ? 1 : 0
    }));
    const raw = {
        org: marker, isp: "Fixture ISP", asn: "AS64500", country_name: "Fixture country",
        city: "Fixture city", hostnames: [marker], domains: ["example.test"], tags: ["fixture"],
        data: [{ port: 443, transport: "tcp", product: "Fixture HTTP", timestamp: "2020-01-02T03:04:05",
            http: { title: marker, server: "Fixture server" },
            ssl: { cert: { subject: { CN: "example.test" }, issuer: { CN: "Fixture issuer" } } },
            data: marker,
            vulns: Object.fromEntries(Array.from({ length: 55 }, (_, i) =>
                [`CVE-2026-${1000 + i}`, { cvss: i ? 8.1 : 0, verified: false, summary: marker }])) }],
        extra: { preserved: "Full response field" }
    };
    const detail = id => ({
        hostId: id, ipAddress: `192.0.2.${id}`, hostnames: [],
        services: id === 1 ? [{ portNumber: 22, detail: "tcp ssh OpenSSH", hostJobId: 12,
            provider: "Nmap", jobUpdatedAt: timestamp }] : [],
        jobs: id < 3 ? [{ hostJobId: id === 1 ? 11 : 21, provider: "Shodan", state: 1,
            updatedAt: timestamp, statusCode: id === 1 ? 200 : 404, retrievedAtUtc: timestamp }] : [],
        paths: id === 1 ? [{ method: "GET", target: marker, count: 101 }] : [],
        requests: id === 1 ? [{ requestId: 101, method: "GET", target: marker,
            queryString: "?full=value&Case=kept", targetHost: "example.test", createdDate: timestamp }] : [],
        nextCursor: id === 1 ? 101 : null
    });
    const originalFetch = window.fetch;
    let fail = false, slow = false, delayedHost = false;
    const requested = [];
    try {
        window.fetch = async (resource, options) => {
            const url = new URL(resource, location.origin);
            requested.push(url.pathname + url.search);
            let body;
            if (url.pathname === "/api/intelligence") {
                if (fail) return new Response('{"error":"Fixture outage"}', { status: 503 });
                const query = url.searchParams.get("query") || "";
                if (slow && query === "slow") await new Promise(resolve => setTimeout(resolve, 200));
                const matches = query === "empty" || query === "slow" ? []
                    : query === "Fixture country" ? hosts.slice(0, 1)
                        : url.searchParams.get("status") === "no-data" ? hosts.slice(1, 2) : hosts;
                const page = Math.min(Number(url.searchParams.get("page") || 0), Math.max(0, Math.ceil(matches.length / 50) - 1));
                body = { summary: { totalHosts: 51, totalRequests: 101, serviceObservations: 2,
                    shodanAvailable: 1, shodanNoData: 1, hostsWithCves: 1, nmapCompleted: 1,
                    shodanPending: 49, shodanRunning: 0, shodanFailed: 0 },
                    countries: [{ name: "Fixture country", hosts: 1 }], organizations: [],
                    hosts: matches.slice(page * 50, (page + 1) * 50), total: matches.length,
                    page, pageSize: 50, loadedAt: timestamp };
            } else if (url.pathname === "/api/sources/1/evidence/11") body = raw;
            else if (url.pathname === "/api/sources/2/evidence/21") body = { error: "No information available for that IP." };
            else if (url.pathname === "/api/sources/1/requests") body = {
                requests: [{ requestId: 100, method: "GET", target: "/older", queryString: "?original=1",
                    targetHost: "example.test", createdDate: timestamp }], nextCursor: null };
            else if (/^\/api\/sources\/\d+$/.test(url.pathname)) {
                const id = Number(url.pathname.split("/").pop());
                if (delayedHost && id === 1) await new Promise(resolve => setTimeout(resolve, 200));
                if (id === 4) return new Response('{"error":"Fixture missing host"}', { status: 404 });
                body = detail(id);
            } else return originalFetch(resource, options);
            return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
        };
        history.replaceState(null, "", "/");
        window.dispatchEvent(new PopStateEvent("popstate"));
        $("intelligence-tab").click();
        await waitFor(idle);
        $("intel-clear").click();
        await waitFor(idle);
        assert($("intel-result").textContent === "1-50 of 51 matching hosts", "Inventory must page all hosts, including hosts without requests.");
        $("intel-next").focus(); $("intel-next").click();
        await waitFor(idle);
        assert($("intel-result").textContent === "51-51 of 51 matching hosts" && $("intel-next").disabled,
            "The final page must remain reachable.");
        $("intel-previous").click(); await waitFor(idle);
        $("intel-countries").querySelector("button").click(); await waitFor(idle);
        assert($("intel-result").textContent === "1-1 of 1 matching hosts", "Country ranks must filter the collection.");
        $("intel-clear").click(); await waitFor(idle);
        change($("intel-state"), "no-data"); await waitFor(idle);
        assert(document.querySelector("#intel-rows .host-link").dataset.hostId === "2", "No-data filter must reach a completed lookup.");
        $("intel-clear").click(); await waitFor(idle);
        change($("intel-sort"), "cves"); await waitFor(idle);
        assert(requested.some(url => url.includes("sort=cves")), "Sort choices must reach the API.");
        change($("intel-search"), "empty", "input");
        await waitFor(() => $("intel-rows").textContent.includes("No hosts match"));
        assert($("intel-previous").disabled && $("intel-next").disabled, "Empty results need disabled pagination.");
        $("intel-clear").click(); await waitFor(idle);
        fail = true; $("intel-refresh").click();
        await waitFor(() => !$("intel-error").hidden && idle());
        assert($("intel-error").textContent.includes("Previous results remain visible") && $("intel-rows").children.length === 50,
            "Collection failure must preserve previous evidence and expose a retry.");
        fail = false; $("intel-refresh").click(); await waitFor(idle);
        slow = true;
        $("intel-search").value = "slow"; $("intel-filters").requestSubmit();
        $("intel-search").value = ""; $("intel-filters").requestSubmit();
        await waitFor(idle);
        await new Promise(resolve => setTimeout(resolve, 250));
        assert($("intel-rows").children.length === 50, "Superseded searches must not replace newer results.");

        const opener = document.querySelector('#intel-rows [data-host-id="1"]');
        opener.focus(); opener.click();
        await waitFor(() => !$("host-tab-overview").disabled);
        assert($("host-dialog").open && $("host-panel-overview").textContent.includes(marker), "Dossier must show full provider context.");
        assert(document.activeElement.id === "host-close", "Opening the modal must put focus on its close control.");
        $("host-tab-overview").focus();
        $("host-tabs").dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
        assert(document.activeElement.id === "host-tab-services" && !$("host-panel-services").hidden,
            "Arrow navigation must select and focus dossier tabs.");
        const services = $("host-panel-services");
        assert(services.querySelectorAll(".service-card").length === 2, "Both providers must remain visible.");
        change(services.querySelector("select"), "Shodan");
        const card = services.querySelector(".service-card");
        assert(services.querySelectorAll(".service-card").length === 1, "Service provider filter must work.");
        card.open = true; await waitFor(() => card.dataset.loaded);
        assert(card.textContent.includes("2020") && card.textContent.includes("2026") && card.textContent.includes("Fixture issuer"),
            "Service details must show distinct observation/retrieval times and TLS metadata.");
        const banner = [...card.querySelectorAll("details")].find(item => item.querySelector("summary").textContent === "Full service banner");
        banner.open = true; await waitFor(() => banner.querySelector("pre"));
        assert(banner.textContent.includes(marker), "Full banners must remain available.");
        $("host-tab-vulnerabilities").click();
        const cves = $("host-panel-vulnerabilities");
        assert(cves.querySelectorAll(".cve-record").length === 50, "Large CVE sets should render incrementally.");
        clickText(cves, "Show more reported CVEs");
        assert(cves.querySelectorAll(".cve-record").length === 55, "Incremental rendering must not hide the rest of the evidence.");
        change(cves.querySelector("select"), "low");
        assert(cves.querySelectorAll(".cve-record").length === 1 && cves.textContent.includes("CVSS 0.0")
            && cves.textContent.includes("Not verified by Shodan"), "Zero scores and false verification flags must not become missing values.");
        $("host-tab-traffic").click();
        const traffic = $("host-panel-traffic");
        clickText(traffic, "Load older requests");
        await waitFor(() => traffic.querySelectorAll(".request-record").length === 2);
        assert(traffic.textContent.includes("?full=value&Case=kept") && requested.includes("/api/sources/1/requests?cursor=101"),
            "Traffic must retain original queries and use the next request cursor.");
        $("host-tab-raw").click();
        clickText($("host-panel-raw"), "View JSON");
        await waitFor(() => !$("host-panel-raw").querySelector("pre").hidden);
        assert(JSON.parse($("host-panel-raw").querySelector("pre").textContent).extra.preserved === "Full response field",
            "Raw JSON must retain fields outside the summarized schema.");
        assert($("host-panel-raw").querySelector("a").getAttribute("href") === "/api/sources/1/evidence/11?download=true",
            "Downloads must identify both the host and its evidence job.");
        assert(!$("host-body").querySelector("img") && !$("intel-rows").querySelector("img") && !window.__intelInjected,
            "Captured markup must remain text throughout the inventory and dossier.");
        const bounds = $("host-dialog").getBoundingClientRect();
        assert(bounds.left >= 0 && bounds.right <= innerWidth && bounds.bottom <= innerHeight,
            "The dossier must fit the viewport.");
        assert($("host-body").scrollWidth <= $("host-body").clientWidth, "Dossier text must not overflow horizontally.");
        $("host-dialog").dispatchEvent(new Event("cancel", { cancelable: true }));
        await waitFor(() => !new URL(location.href).searchParams.has("host"));
        assert(!$("host-dialog").open && document.activeElement === opener, "Escape dismissal must restore the source link's focus.");

        const navigate = id => {
            history.replaceState(null, "", `/?host=${id}&panel=overview`);
            window.dispatchEvent(new PopStateEvent("popstate"));
        };
        delayedHost = true; navigate(1); navigate(2);
        await waitFor(() => $("host-title").textContent === "192.0.2.2" && !$("host-tab-overview").disabled);
        await new Promise(resolve => setTimeout(resolve, 250));
        assert($("host-title").textContent === "192.0.2.2" && $("host-panel-overview").textContent.includes("no information"),
            "A superseded host load must not overwrite a no-data dossier.");
        navigate(3); await waitFor(() => $("host-title").textContent === "192.0.2.3" && !$("host-tab-overview").disabled);
        assert($("host-panel-overview").textContent.includes("No Shodan response"), "Hosts without lookups must remain inspectable.");
        navigate(4); await waitFor(() => $("host-body").textContent.includes("Fixture missing host"));
        assert($("host-body").textContent.includes("Retry loading"), "Missing host evidence must expose an error and retry.");
        $("host-close").click();
        assert(!new URL(location.href).searchParams.has("host"), "Closing a direct link must clear its host route.");
        assert(document.documentElement.scrollWidth <= innerWidth, "Only the inventory table may scroll horizontally.");
        return { result: "passed", mode: "offline API fixtures", viewport: [innerWidth, innerHeight],
            checks: ["all-host pagination", "facets and filters", "empty and error states", "search race",
                "modal focus and keyboard tabs", "provider services and TLS", "full CVE browsing",
                "request pagination", "complete JSON", "captured markup", "host race", "direct links", "responsive fit"] };
    } finally {
        window.fetch = originalFetch;
        history.replaceState(null, "", "/");
        window.dispatchEvent(new PopStateEvent("popstate"));
    }
})()
