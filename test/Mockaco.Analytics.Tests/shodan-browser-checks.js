// Evaluate on a locally served atlas. Only the API is replaced with explicit offline fixtures.
(async () => {
    const $ = id => document.getElementById(id);
    const assert = (condition, message) => { if (!condition) throw new Error(message); };
    const waitFor = async predicate => {
        const deadline = Date.now() + 10000;
        while (!predicate()) {
            if (Date.now() > deadline) throw new Error("Timed out waiting for fixture rendering.");
            await new Promise(resolve => setTimeout(resolve, 25));
        }
    };
    const observed = "2020-01-02T03:04:05+00:00";
    const retrieved = "2026-10-30T12:00:00+00:00";
    const marker = '<img src="data:," onerror="window.__shodanInjected=true">';
    const sources = [1, 2].map(id => ({
        hostId: id, ipAddress: `192.0.2.${id}`, requests: 3 - id,
        firstSeen: retrieved, lastSeen: retrieved, dominantFamily: "Site discovery",
        families: ["Site discovery"], services: id === 1 ? ["https", "ssh"] : [],
        pathCount: 1, fingerprint: `fixture-${id}`, fingerprintLabel: "GET /", x: id, y: id
    }));
    const detail = id => ({
        hostId: id, ipAddress: `192.0.2.${id}`, hostnames: [],
        services: id === 1 ? [
            { portNumber: 443, detail: `tcp https\n${marker}`, hostJobId: 11,
                jobUpdatedAt: retrieved, provider: "Shodan", observedAtUtc: observed, retrievedAtUtc: retrieved },
            { portNumber: 22, detail: "tcp ssh OpenSSH", hostJobId: 12,
                jobUpdatedAt: retrieved, provider: "Nmap", observedAtUtc: null, retrievedAtUtc: null }
        ] : [],
        jobs: [{ hostJobId: id === 1 ? 11 : 21, state: 1, updatedAt: retrieved, lastError: null,
            provider: "Shodan", statusCode: id === 1 ? 200 : 404, retrievedAtUtc: retrieved }],
        paths: [], requests: [], nextCursor: null
    });
    const originalFetch = window.fetch;
    try {
        window.fetch = async (resource, options) => {
            const path = new URL(resource, location.origin).pathname;
            let body;
            if (path === "/api/snapshot") body = {
                sources, requestCount: 3, firstSeen: retrieved, lastSeen: retrieved,
                explainedVariance: 1, loadedAt: retrieved, unattributedRequests: 0
            };
            else if (path.endsWith("/neighbors")) body = [];
            else if (/^\/api\/sources\/[12]$/.test(path)) body = detail(Number(path.split("/").pop()));
            else return originalFetch(resource, options);
            return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
        };
        $("behavior-tab")?.click();
        await waitFor(() => !$("refresh").disabled);
        $("refresh").click();
        await waitFor(() => document.querySelector('#source-rows button[data-host-id="1"]'));
        document.querySelector('#source-rows button[data-host-id="1"]').click();
        await waitFor(() => $("inspector-content").textContent.includes(marker));
        const text = $("inspector-content").textContent;
        assert(text.includes("Port 443 / Shodan") && text.includes("Port 22 / Nmap"), "Providers must be visible per service.");
        assert(text.includes("Shodan observed:") && text.includes("2020") && text.includes("Retrieved:") && text.includes("2026"),
            "Old observation time and current retrieval time must be distinguishable.");
        assert(text.includes("not a new scan"), "Lookup provenance must not imply a fresh scan.");
        assert(!$("inspector-content").querySelector("img") && !window.__shodanInjected, "Shodan banners must render as text.");
        document.querySelector('#source-rows button[data-host-id="2"]').click();
        await waitFor(() => $("inspector-content").textContent.includes("no host information"));
        assert($("inspector-content").textContent.includes("Shodan job #21: Completed"), "No-data must show as completed, not failed.");
        assert(!$("inspector-content").textContent.includes("Port 443"), "No-data must not retain the previous source's services.");
        return { result: "passed", mode: "offline API fixtures",
            checks: ["provider labels", "observed versus retrieved dates", "banner text", "completed no-data"] };
    } finally {
        window.fetch = originalFetch;
    }
})()
