// Offline API fixtures only. Every write is intercepted; nothing is purged from the real database.
(async () => {
    const $ = id => document.getElementById(id);
    const assert = (condition, message) => { if (!condition) throw new Error(message); };
    const waitFor = async predicate => {
        const deadline = Date.now() + 10000;
        while (!predicate()) {
            if (Date.now() > deadline) throw new Error("Timed out waiting for cleanup UI.");
            await new Promise(resolve => setTimeout(resolve, 25));
        }
    };
    assert($("intel-cleanup"), "Missing non-public host cleanup action.");
    const marker = '<img src="data:," onerror="window.__cleanupInjected=true">';
    const candidates = Array.from({ length: 51 }, (_, i) => ({
        hostId: i + 1, ipAddress: i === 50 ? marker : `192.168.1.${i + 1}`,
        reason: i === 50 ? "Malformed address" : "Private-use"
    }));
    const counts = { hosts: 51, requests: 51, headers: 51, jobs: 51, discoveries: 0, hostnames: 0, evidence: 0 };
    const timestamp = "2026-11-01T00:00:00+00:00";
    const originalFetch = window.fetch;
    let purged = false, failPreview = true, failPurge = true, writes = 0, snapshots = 0;
    try {
        window.fetch = async (resource, options) => {
            const url = new URL(resource, location.origin);
            let body;
            if (url.pathname === "/api/intelligence/non-public-hosts") {
                if (failPreview) return new Response('{"error":"Fixture preview outage"}', { status: 503 });
                body = { hosts: purged ? [] : candidates, counts: purged
                    ? { hosts: 0, requests: 0, headers: 0, jobs: 0, discoveries: 0, hostnames: 0, evidence: 0 } : counts };
            } else if (url.pathname === "/api/intelligence/non-public-hosts/purge") {
                writes++;
                assert(options?.method === "POST" && options.headers["Content-Type"] === "application/json", "Purge must be an explicit JSON mutation.");
                assert(JSON.stringify(JSON.parse(options.body).hostIds) === JSON.stringify(candidates.map(host => host.hostId)),
                    "Only the complete reviewed host selection may be submitted.");
                if (failPurge) return new Response('{"error":"Fixture purge failure"}', { status: 500 });
                purged = true; body = counts;
            } else if (options?.method && options.method !== "GET") throw new Error("Unexpected write blocked by fixture.");
            else if (url.pathname === "/api/intelligence") {
                const hosts = [...(purged ? [] : candidates), { hostId: 99, ipAddress: "8.8.8.8" }]
                    .map(host => ({ ...host, requests: 1, portCount: 0, cveCount: 0, lastSeen: timestamp }));
                body = { hosts: hosts.slice(0, 50), total: hosts.length, page: 0, pageSize: 50, loadedAt: timestamp,
                    countries: [], organizations: [], summary: { totalHosts: hosts.length, totalRequests: hosts.length,
                        serviceObservations: 0, shodanAvailable: 0, shodanNoData: 0, hostsWithCves: 0, nmapCompleted: 0,
                        shodanPending: 0, shodanRunning: 0, shodanFailed: 0 } };
            } else if (url.pathname === "/api/snapshot") {
                snapshots++;
                body = { sources: [], requestCount: purged ? 1 : 52, firstSeen: timestamp, lastSeen: timestamp,
                    loadedAt: timestamp, explainedVariance: 0, unattributedRequests: 0 };
            } else return originalFetch(resource, options);
            return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
        };
        $("behavior-tab").click();
        await waitFor(() => snapshots > 0 && !$("refresh").disabled);
        $("intelligence-tab").click();
        await waitFor(() => !$("intel-refresh").disabled);
        $("intel-refresh").click();
        await waitFor(() => !$("intel-refresh").disabled);
        $("intel-cleanup").focus(); $("intel-cleanup").click();
        await waitFor(() => !$("cleanup-error").hidden);
        assert(writes === 0 && $("cleanup-purge").disabled, "Opening or failing a preview must never purge.");
        failPreview = false; $("cleanup-refresh").click();
        await waitFor(() => !$("cleanup-purge").disabled);
        assert($("cleanup-rows").children.length === 50, "Preview must initially render one page.");
        $("cleanup-more").click();
        assert($("cleanup-rows").children.length === 51 && $("cleanup-rows").textContent.includes(marker)
            && !$("cleanup-rows").querySelector("img") && !window.__cleanupInjected,
            "All reviewed addresses must be available as text, including malformed values.");
        $("cleanup-purge").click();
        await waitFor(() => !$("cleanup-error").hidden && !$("cleanup-purge").disabled);
        assert(writes === 1 && !purged, "Failed purge must retain a usable reviewed selection.");
        failPurge = false; $("cleanup-purge").click();
        await waitFor(() => $("intel-result").textContent === "1-1 of 1 matching hosts" && !$("cleanup-refresh").disabled);
        assert(writes === 2 && $("cleanup-purge").disabled, "Successful purge must consume its selection and reload the collection.");
        assert($("cleanup-status").textContent.includes("51") && $("intel-maintenance-status").textContent.includes("51"),
            "Show deletion results in both the dialog and collection.");
        const bounds = $("cleanup-dialog").getBoundingClientRect();
        assert(bounds.left >= 0 && bounds.right <= innerWidth && bounds.bottom <= innerHeight, "Cleanup dialog must fit the viewport.");
        $("cleanup-dialog").dispatchEvent(new Event("cancel", { cancelable: true }));
        assert(!$("cleanup-dialog").open && document.activeElement === $("intel-cleanup"), "Dismissal must restore opener focus.");
        const before = snapshots;
        $("behavior-tab").click();
        await waitFor(() => snapshots > before && !$("refresh").disabled);
        $("intelligence-tab").click(); $("intel-cleanup").click();
        await waitFor(() => !$("cleanup-refresh").disabled);
        assert($("cleanup-purge").disabled && $("cleanup-rows").textContent.includes("No non-public hosts"),
            "An empty fresh preview must not permit another purge.");
        $("cleanup-close").click();
        assert(document.documentElement.scrollWidth <= innerWidth, "Cleanup controls must not widen the page.");
        return { result: "passed", mode: "offline fixtures; no real writes", viewport: [innerWidth, innerHeight],
            checks: ["preview-only open", "preview retry", "full candidate browsing", "captured text", "explicit selection",
                "purge failure retry", "inventory and behavior refresh", "empty state", "focus and responsive dialog"] };
    } finally {
        window.fetch = originalFetch;
        if ($("cleanup-dialog")?.open) $("cleanup-close").click();
    }
})()
