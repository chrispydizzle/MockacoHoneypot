(async () => {
    const $ = id => document.getElementById(id);
    const assert = (condition, message) => { if (!condition) throw new Error(message); };
    const paint = () => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    const input = (id, value) => {
        $(id).value = value;
        $(id).dispatchEvent(new Event("input", { bubbles: true }));
    };
    $("behavior-tab")?.click();
    const deadline = Date.now() + 30000;
    while (!$("chart-message").hidden) {
        if (Date.now() > deadline) throw new Error("Snapshot did not load.");
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    if (!$("clear-selection").hidden) $("clear-selection").click();
    input("service-search", "");
    await paint();

    for (const id of ["apply", "refresh", "zoom-in", "zoom-out", "view-groups", "view-sources"]) {
        const bounds = $(id).getBoundingClientRect();
        assert(bounds.height >= 44 && bounds.width >= 44, `${id} needs a 44px pointer target.`);
    }
    assert(parseFloat(getComputedStyle(document.querySelector(".panel-description")).fontSize) >= (innerWidth <= 520 ? 16 : 14),
        "Explanatory text must remain readable at desktop and mobile sizes.");
    const initial = [...document.querySelectorAll(".service-heading")].map(node => node.dataset.focusKey);
    assert(initial.length <= 8 && initial.length > 0, "The matrix must render a service page, not thousands of hidden columns.");
    const cell = [...document.querySelectorAll(".matrix-cell")].find(node =>
        node.dataset.family === "Site discovery" && node.dataset.service === "ssh");
    assert(cell, "Expected a populated site-discovery/SSH cell.");
    const originalHeat = cell.style.getPropertyValue("--heat");
    cell.click();
    const selectedCount = $("source-count").textContent;
    $("next-services").focus();
    $("next-services").click();
    assert($("source-count").textContent === selectedCount, "Changing service pages must not change the selected cohort.");
    assert(document.activeElement.id === "next-services", "Pager focus must survive rendering.");
    const next = [...document.querySelectorAll(".service-heading")].map(node => node.dataset.focusKey);
    assert(next.length && next.every(key => !initial.includes(key)), "Next service page must expose new columns.");
    const lastPage = $("service-page").options.length - 1;
    assert(lastPage > 1, "Expected the full captured service population to remain available.");
    $("service-page").value = String(lastPage);
    $("service-page").dispatchEvent(new Event("change"));
    assert($("next-services").disabled, "Last service page must be reachable without losing data.");
    $("service-page").value = "0";
    $("service-page").dispatchEvent(new Event("change"));
    assert(document.querySelector('.matrix-cell[aria-pressed="true"]')?.dataset.service === "ssh",
        "Returning to a service page must preserve its cell selection.");
    input("service-search", "ssh");
    assert(document.querySelector('.matrix-cell[aria-pressed="true"]').style.getPropertyValue("--heat") === originalHeat,
        "Searching service columns must not rescale the matrix heat.");
    $("clear-selection").click();

    const snapshot = await (await fetch("/api/snapshot")).json();
    const rare = snapshot.sources.flatMap(source => source.services)
        .find(service => service.startsWith("unidentified:") && !initial.includes(`service:${service}`));
    assert(rare, "Expected an observed service outside the first page.");
    input("service-search", rare);
    assert([...document.querySelectorAll(".service-heading")].some(node => node.dataset.focusKey === `service:${rare}`),
        "Service search must cover the full dataset, not only rendered columns.");
    input("service-search", "");

    $("pan-menu").querySelector("summary").click();
    const canvas = $("constellation");
    assert(document.querySelector(".axis-label").getBoundingClientRect().top >= canvas.getBoundingClientRect().bottom,
        "The projection annotation must not cover plotted sources on small screens.");
    await paint();
    const context = canvas.getContext("2d");
    const originalClear = context.clearRect;
    let hoverRedraws = 0;
    context.clearRect = function (...args) { hoverRedraws++; return originalClear.apply(this, args); };
    const bounds = canvas.getBoundingClientRect();
    for (let index = 0; index < 100; index++)
        canvas.dispatchEvent(new PointerEvent("pointermove", { clientX: bounds.left + index, clientY: bounds.top + 100 }));
    await paint();
    context.clearRect = originalClear;
    assert(hoverRedraws === 0, "Hovering must not repaint the entire constellation.");
    const beforePan = canvas.toDataURL();
    $("pan-right").click();
    await paint();
    assert(canvas.toDataURL() !== beforePan, "A single-pointer pan button must move the plotted view.");
    $("pan-menu").open = false;
    $("reset-view").click();
    await paint();
    input("minimum", String(Math.max(...snapshot.sources.map(source => source.requests)) + 1));
    assert(!document.querySelector(".matrix-cell") && $("service-page").disabled,
        "Changing cohort filters must invalidate the cached aggregation and clamp service pages.");
    input("minimum", "1");
    assert($("source-count").textContent === `${snapshot.sources.length.toLocaleString()} sources`,
        "Clearing a cohort filter must restore the full capture.");
    const colorContext = document.createElement("canvas").getContext("2d", { willReadFrequently: true });
    const color = value => {
        colorContext.clearRect(0, 0, 1, 1);
        colorContext.fillStyle = value;
        colorContext.fillRect(0, 0, 1, 1);
        return [...colorContext.getImageData(0, 0, 1, 1).data];
    };
    const luminance = channels => channels.slice(0, 3).map(value => {
        value /= 255;
        return value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4;
    }).reduce((sum, value, index) => sum + value * [.2126, .7152, .0722][index], 0);
    let minimumContrast = Infinity;
    for (const node of document.querySelectorAll(".panel-description, .matrix-cell, .legend button, .toolbar label")) {
        let backgroundNode = node;
        while (color(getComputedStyle(backgroundNode).backgroundColor)[3] === 0)
            backgroundNode = backgroundNode.parentElement;
        const foreground = luminance(color(getComputedStyle(node).color));
        const background = luminance(color(getComputedStyle(backgroundNode).backgroundColor));
        const contrast = (Math.max(foreground, background) + .05) / (Math.min(foreground, background) + .05);
        minimumContrast = Math.min(minimumContrast, contrast);
        assert(contrast >= 4.5, `${node.textContent} needs 4.5:1 text contrast; got ${contrast.toFixed(2)}.`);
    }
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
        assert(getComputedStyle($("apply")).transitionDuration.split(",").every(value => parseFloat(value) === 0),
            "Reduced motion must disable ornamental transitions.");
    }
    assert(document.documentElement.scrollWidth <= innerWidth, "The page must fit the viewport; only data regions may scroll horizontally.");
    return { result: "passed", viewport: [innerWidth, innerHeight], pixelRatio: devicePixelRatio,
        reducedMotion: matchMedia("(prefers-reduced-motion: reduce)").matches,
        minimumTextContrast: Number(minimumContrast.toFixed(2)), servicePages: lastPage + 1,
        renderedCells: document.querySelectorAll(".matrix-cell").length,
        checks: ["readable text", "44px controls", "bounded rendering", "complete service browsing",
            "selection and focus continuity", "full-data search", "pointer pan", "reduced motion", "page fit"] };
})()
