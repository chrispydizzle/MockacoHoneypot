export function utcTimestamp(value) {
    if (!value) return "Not reported";
    const text = String(value);
    const zoned = /(?:Z|[+-]\d{2}:\d{2})$/i.test(text) ? text : text + "Z";
    const time = new Date(zoned);
    return Number.isNaN(time.valueOf()) ? text : time.toISOString().slice(0, 19).replace("T", " ") + " UTC";
}

export function lookupState(host) {
    if (host.statusCode === 200) return { label: "Available", tone: "available" };
    if (host.statusCode === 404) return { label: "No data", tone: "neutral" };
    return ({ 0: { label: "Pending", tone: "pending" }, 1: { label: "Completed", tone: "neutral" },
        2: { label: "Running", tone: "pending" }, 3: { label: "Failed", tone: "warning" } })[host.shodanState]
        || { label: "Not looked up", tone: "neutral" };
}

export function latestEvidence(jobs) {
    return jobs.filter(job => job.provider === "Shodan" && job.statusCode && job.retrievedAtUtc)
        .sort((a, b) => Date.parse(b.retrievedAtUtc) - Date.parse(a.retrievedAtUtc) || b.hostJobId - a.hostJobId)[0] || null;
}

export function summarizeEvidence(raw) {
    const services = Array.isArray(raw?.data) ? raw.data.filter(item => item && typeof item === "object") : [];
    const vulnerabilities = new Map();
    const collect = (values, port) => {
        const entries = Array.isArray(values) ? values.map(id => [id, {}])
            : values && typeof values === "object" ? Object.entries(values) : [];
        for (const [id, value] of entries) {
            if (typeof id !== "string" || !id.startsWith("CVE-")) continue;
            const detail = value && typeof value === "object" ? value : {};
            const item = vulnerabilities.get(id) || { id, score: null, verified: null, summary: "", ports: [] };
            const score = detail.cvss ?? detail.cvss_v3;
            if (score !== undefined && score !== null && Number.isFinite(Number(score)))
                item.score = Math.max(item.score ?? 0, Number(score));
            if (typeof detail.verified === "boolean") item.verified = item.verified === true || detail.verified;
            if (detail.summary) item.summary = String(detail.summary);
            if (port && !item.ports.includes(port)) item.ports.push(port);
            vulnerabilities.set(id, item);
        }
    };
    collect(raw?.vulns);
    for (const service of services)
        collect(service.vulns, service.port ? `${service.port}/${service.transport || "unknown"}` : null);
    for (const item of vulnerabilities.values()) item.ports.sort((a, b) => parseInt(a) - parseInt(b) || a.localeCompare(b));
    return { services, vulnerabilities: [...vulnerabilities.values()]
        .sort((a, b) => (b.score ?? -1) - (a.score ?? -1) || a.id.localeCompare(b.id)) };
}
