// Evaluate with agent-browser eval -b on the running atlas; reports interaction-to-paint, not Web Vitals INP.
(async () => {
    const $ = id => document.getElementById(id);
    const paint = () => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    const input = (id, value) => {
        $(id).value = value;
        $(id).dispatchEvent(new Event("input", { bubbles: true }));
    };
    if (!$("chart-message").hidden) throw new Error("Wait for the snapshot to load before measuring.");
    document.activeElement?.blur();
    window.scrollTo({ top: 0, left: 0, behavior: "instant" });
    if (!$("clear-selection").hidden) $("clear-selection").click();
    input("service-search", "");
    await paint();
    const cells = document.querySelectorAll(".matrix-cell").length;
    const samples = [];
    for (let index = 0; index < 5; index++) {
        const cell = [...document.querySelectorAll(".matrix-cell")]
            .find(node => node.dataset.family === "Site discovery" && node.dataset.service === "ssh");
        if (!cell) throw new Error("Expected the site-discovery/SSH cell in the first service page.");
        const start = performance.now();
        cell.click();
        await paint();
        samples.push(performance.now() - start);
    }
    if (!$("clear-selection").hidden) $("clear-selection").click();
    const searchStart = performance.now();
    input("service-search", "ssh");
    await paint();
    const searchMs = performance.now() - searchStart;
    input("service-search", "");
    await paint();
    const controls = ["apply", "refresh", "zoom-in", "zoom-out", "view-groups"].map(id => {
        const rect = $(id).getBoundingClientRect();
        return { id, width: Math.round(rect.width), height: Math.round(rect.height) };
    });
    samples.sort((a, b) => a - b);
    return {
        viewport: [innerWidth, innerHeight], scrollY, renderedMatrixCells: cells,
        selectionPaintMedianMs: Math.round(samples[2]), selectionPaintSamplesMs: samples.map(Math.round),
        searchPaintMs: Math.round(searchMs), controls,
        bodyTextPx: getComputedStyle(document.querySelector(".panel-description")).fontSize,
        pageOverflowPx: document.documentElement.scrollWidth - innerWidth
    };
})()
