(async () => {
    const $ = id => document.getElementById(id);
    const assert = (condition, message) => { if (!condition) throw new Error(message); };
    const waitFor = async predicate => {
        const deadline = Date.now() + 30000;
        while (!predicate()) {
            if (Date.now() > deadline) throw new Error("Timed out waiting for the dashboard.");
            await new Promise(resolve => setTimeout(resolve, 50));
        }
    };
    const input = (id, value) => {
        $(id).value = value;
        $(id).dispatchEvent(new Event("input", { bubbles: true }));
    };
    $("behavior-tab")?.click();
    await waitFor(() => $("chart-message").hidden);
    input("service-search", "ssh");
    const cell = [...document.querySelectorAll(".matrix-cell")]
        .find(item => item.dataset.family === "Site discovery" && item.dataset.service === "ssh" && +item.dataset.count);
    assert(cell, "Expected a nonempty site-discovery/SSH cell in this database.");
    const expectedCount = +cell.dataset.count;
    cell.focus();
    cell.click();
    assert($("source-count").textContent === `${expectedCount.toLocaleString()} sources`, "Cell selection must show exactly its source count.");
    assert(document.activeElement.dataset.family === "Site discovery" && document.activeElement.dataset.service === "ssh",
        "Keyboard focus must survive matrix selection and rerender.");
    $("matrix-mode").value = "percent";
    $("matrix-mode").dispatchEvent(new Event("change"));
    assert(document.querySelector('.matrix-cell[aria-pressed="true"]').textContent.endsWith("%"), "Percent mode must preserve the selected cell.");
    $("clear-selection").click();
    input("service-search", "");
    const firstSource = document.querySelector("#source-rows button");
    const selectedId = firstSource.dataset.hostId;
    firstSource.focus();
    firstSource.click();
    await waitFor(() => [...document.querySelectorAll("#inspector-content h3")].some(node => node.textContent === "Captured requests"));
    assert(document.activeElement.dataset.hostId === selectedId, "Keyboard focus must survive source-row selection.");
    assert(document.querySelectorAll(".neighbor-button").length > 0, "Source details should show similarity matches.");
    const requestsSection = [...document.querySelectorAll("#inspector-content section")]
        .find(node => node.querySelector("h3")?.textContent === "Captured requests");
    const before = requestsSection.querySelectorAll("details").length;
    const more = [...requestsSection.querySelectorAll("button")].find(node => node.textContent === "Load older requests");
    assert(more && !more.hidden, "Busiest source should have another request page.");
    more.click();
    await waitFor(() => requestsSection.querySelectorAll("details").length > before);
    const ids = [...requestsSection.querySelectorAll("summary")].map(node => node.textContent.split(" ")[0]);
    assert(new Set(ids).size === ids.length, "Request pagination must not duplicate records.");

    const originalFetch = window.fetch;
    const marker = '<img src="data:," onerror="window.__atlasInjected=true">';
    const sample = await (await originalFetch(`/api/sources/${selectedId}`)).json();
    sample.paths[0].target = marker;
    sample.hostnames.push(marker);
    sample.requests[0].queryString = marker;
    try {
        window.fetch = (resource, options) => String(resource).includes(`/api/sources/${selectedId}?`)
            ? Promise.resolve(new Response(JSON.stringify(sample), { headers: { "Content-Type": "application/json" } }))
            : originalFetch(resource, options);
        document.querySelector("#source-rows button").click();
        await waitFor(() => $("inspector-content").textContent.includes(marker));
        assert(!$("inspector-content").querySelector("img") && !window.__atlasInjected,
            "Captured markup must render as evidence text, never executable HTML.");
    } finally {
        window.fetch = originalFetch;
    }
    const evidenceUrls = [];
    try {
        window.fetch = async (resource, options) => {
            const url = String(resource);
            if (url.includes("/api/snapshot") && url.includes("from=2030-01-01"))
                await new Promise(resolve => setTimeout(resolve, 200));
            if (url.includes("/api/sources/")) evidenceUrls.push(url);
            return originalFetch(resource, options);
        };
        input("from", "2030-01-01"); input("before", "2031-01-01");
        $("filters").dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
        input("from", "2024-01-01"); input("before", "2023-01-01");
        $("filters").dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
        await waitFor(() => !$("error").hidden && !$("apply").disabled);
        document.querySelector("#source-rows button").click();
        await waitFor(() => evidenceUrls.length > 0);
        assert(evidenceUrls.every(url => !url.includes("from=2030")),
            "A superseded failed date change must not change the evidence window of the displayed snapshot.");
    } finally {
        window.fetch = originalFetch;
        $("all-time").click();
    }
    await waitFor(() => $("chart-message").hidden && !$("apply").disabled);
    assert(document.documentElement.scrollWidth <= window.innerWidth, "The page must not overflow horizontally.");
    return { result: "passed", matrixSources: expectedCount, paginatedRequests: ids.length,
        checks: ["matrix selection", "row percentages", "keyboard focus", "source evidence", "request pagination", "captured markup", "date-change race", "page overflow"] };
})()
