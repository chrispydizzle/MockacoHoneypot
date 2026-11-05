import test from "node:test";
import assert from "node:assert/strict";
import { buildMatrix, filterSources, servicePage, NO_OBSERVATIONS } from "../../src/Mockaco.Analytics/wwwroot/model.mjs";

const sources = [
    { hostId: 1, ipAddress: "192.0.2.1", requests: 100, fingerprint: "a", families: ["PHP", "Login", "PHP"], services: ["ssh", "ssh", "http"] },
    { hostId: 2, ipAddress: "192.0.2.2", requests: 1, fingerprint: "a", families: ["PHP"], services: [] },
    { hostId: 3, ipAddress: "198.51.100.1", requests: 5, fingerprint: "b", families: ["Login"], services: ["unknown"] }
];

test("matrix counts distinct sources rather than requests or repeated service observations", () => {
    const matrix = buildMatrix(sources);
    const php = matrix.rows.find(row => row.family === "PHP");
    assert.equal(php.total, 2);
    assert.equal(php.cells.get("ssh"), 1);
    assert.equal(php.cells.get(NO_OBSERVATIONS), 1);
    assert.equal(matrix.rows.find(row => row.family === "Login").cells.get("unknown"), 1);
    assert.equal(matrix.columns.find(column => column.service === "ssh").total, 1);
});

test("cell selection intersects behavior with services without treating missing recon as unknown", () => {
    assert.deepEqual(filterSources(sources, { family: "PHP", service: "ssh" }).map(s => s.hostId), [1]);
    assert.deepEqual(filterSources(sources, { service: NO_OBSERVATIONS }).map(s => s.hostId), [2]);
    assert.deepEqual(filterSources(sources, { service: "unknown" }).map(s => s.hostId), [3]);
    assert.deepEqual(filterSources(sources, { family: "PHP", service: "unknown" }), []);
});

test("search, minimum volume and fingerprint filters compose", () => {
    assert.deepEqual(filterSources(sources, { query: "192.0.2.", minimum: 2, fingerprint: "a" }).map(s => s.hostId), [1]);
    assert.deepEqual(filterSources(sources, { fingerprint: "b" }).map(s => s.hostId), [3]);
    assert.equal(filterSources(sources, {}).length, 3);
    assert.deepEqual(buildMatrix([]), { columns: [], rows: [] });
});

test("service pages expose every column once and clamp after a cohort shrinks", () => {
    const columns = ["http", "ssh", "ftp", "smtp", "unknown"].map(service => ({ service, total: 1 }));
    const first = servicePage(columns, "", 0, 2);
    const second = servicePage(columns, "", 1, 2);
    const last = servicePage(columns, "", 20, 2);
    assert.deepEqual(first.items.map(item => item.service), ["http", "ssh"]);
    assert.deepEqual(second.items.map(item => item.service), ["ftp", "smtp"]);
    assert.deepEqual(last.items.map(item => item.service), ["unknown"]);
    assert.equal(last.page, 2);
    assert.equal(last.pages, 3);
    assert.equal(last.start, 5);
    assert.equal(last.end, 5);
    assert.deepEqual([...first.items, ...second.items, ...last.items], columns);
});

test("service search applies before paging and recognizes the displayed no-observations label", () => {
    const columns = ["http", "ssh", "https", NO_OBSERVATIONS].map(service => ({ service, total: 1 }));
    const page = servicePage(columns, " HTTP ", 1, 1);
    assert.deepEqual(page.items.map(item => item.service), ["https"]);
    assert.equal(page.total, 2);
    assert.equal(servicePage(columns, "no observations", 0, 2).items[0].service, NO_OBSERVATIONS);
    const empty = servicePage(columns, "missing", 9, 2);
    assert.deepEqual(empty.items, []);
    assert.equal(empty.page, 0);
    assert.equal(empty.start, 0);
    assert.equal(empty.end, 0);
});
