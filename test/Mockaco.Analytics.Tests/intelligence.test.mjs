import test from "node:test";
import assert from "node:assert/strict";
import { summarizeEvidence, utcTimestamp, lookupState, latestEvidence } from "../../src/Mockaco.Analytics/wwwroot/intelligence-model.mjs";

test("CVE evidence merges host and service records without losing false verification or zero scores", () => {
    const result = summarizeEvidence({
        vulns: ["CVE-2025-0001", "CVE-2025-0002"],
        data: [
            { port: 443, transport: "tcp", vulns: {
                "CVE-2025-0001": { cvss: 0, verified: false, summary: "Reported only" }
            } },
            { port: 80, transport: "tcp", vulns: {
                "CVE-2025-0001": { cvss: 0, verified: false },
                "CVE-2025-0003": { cvss: 9.8, verified: true, summary: "A service report" }
            } }
        ]
    });
    assert.equal(result.vulnerabilities.length, 3);
    assert.equal(result.vulnerabilities[0].id, "CVE-2025-0003");
    const first = result.vulnerabilities.find(item => item.id === "CVE-2025-0001");
    assert.equal(first.score, 0);
    assert.equal(first.verified, false);
    assert.deepEqual(first.ports, ["80/tcp", "443/tcp"]);
    assert.equal(result.vulnerabilities.find(item => item.id === "CVE-2025-0002").verified, null);
});

test("service metadata remains available and missing/no-data records do not fabricate intel", () => {
    const raw = { org: "Example", data: [{ port: 443, transport: "tcp", product: "nginx",
        ssl: { cert: { subject: { CN: "example.test" } } }, http: { title: "<b>hello</b>" } }] };
    const result = summarizeEvidence(raw);
    assert.equal(result.services[0], raw.data[0]);
    assert.equal(result.services[0].http.title, "<b>hello</b>");
    assert.deepEqual(summarizeEvidence({ error: "No information available for that IP." }).services, []);
    assert.deepEqual(summarizeEvidence(null).vulnerabilities, []);
    assert.deepEqual(summarizeEvidence({ vulns: { "CVE-2025-0004": { cvss: "7.5" } }, data: [null, "bad"] })
        .vulnerabilities.map(item => item.score), [7.5]);
});

test("Shodan timestamps without zones are explicitly UTC, not local or retrieval time", () => {
    assert.equal(utcTimestamp("2020-01-02T03:04:05.123456"), "2020-01-02 03:04:05 UTC");
    assert.equal(utcTimestamp("2020-01-02T04:04:05+01:00"), "2020-01-02 03:04:05 UTC");
    assert.equal(utcTimestamp(null), "Not reported");
    assert.equal(utcTimestamp("not a timestamp"), "not a timestamp");
});

test("no-data, pending, failures, and completed zero-port records are distinct", () => {
    assert.equal(lookupState({ statusCode: 404, shodanState: 1 }).label, "No data");
    assert.equal(lookupState({ statusCode: 200, shodanState: 1 }).label, "Available");
    assert.equal(lookupState({ shodanState: 0 }).label, "Pending");
    assert.equal(lookupState({ shodanState: 2 }).label, "Running");
    assert.equal(lookupState({ shodanState: 3 }).label, "Failed");
    assert.equal(lookupState({}).label, "Not looked up");
});

test("latest evidence uses retrieval order rather than assuming job IDs are chronological", () => {
    const old = { hostJobId: 20, provider: "Shodan", statusCode: 200, retrievedAtUtc: "2020-01-01T00:00:00Z" };
    const recent = { hostJobId: 10, provider: "Shodan", statusCode: 404, retrievedAtUtc: "2026-01-01T00:00:00Z" };
    assert.equal(latestEvidence([old, recent, { hostJobId: 99, provider: "Nmap" }]), recent);
    assert.equal(latestEvidence([]), null);
});
