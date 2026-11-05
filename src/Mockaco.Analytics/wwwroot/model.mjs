export const NO_OBSERVATIONS = "(no service observations)";

export function servicePage(columns, query = "", page = 0, size = 8) {
    query = query.trim().toLowerCase();
    const matches = columns.filter(column => column.service.toLowerCase().includes(query) ||
        (column.service === NO_OBSERVATIONS && "no observations".includes(query)));
    const pages = Math.max(1, Math.ceil(matches.length / size));
    page = Math.max(0, Math.min(page, pages - 1));
    return {
        items: matches.slice(page * size, (page + 1) * size),
        page, pages, total: matches.length,
        start: matches.length ? page * size + 1 : 0,
        end: Math.min((page + 1) * size, matches.length)
    };
}

export function buildMatrix(sources) {
    const rows = new Map();
    const columns = new Map();
    for (const source of sources) {
        const services = new Set(source.services.length ? source.services : [NO_OBSERVATIONS]);
        for (const service of services) columns.set(service, (columns.get(service) || 0) + 1);
        for (const family of new Set(source.families)) {
            if (!rows.has(family)) rows.set(family, { family, total: 0, cells: new Map() });
            const row = rows.get(family);
            row.total++;
            for (const service of services) row.cells.set(service, (row.cells.get(service) || 0) + 1);
        }
    }
    return {
        columns: [...columns].map(([service, total]) => ({ service, total }))
            .sort((a, b) => b.total - a.total || a.service.localeCompare(b.service)),
        rows: [...rows.values()].sort((a, b) => b.total - a.total || a.family.localeCompare(b.family))
    };
}

export function filterSources(sources, filters = {}) {
    const query = (filters.query || "").trim().toLowerCase();
    return sources.filter(source =>
        (!query || source.ipAddress.toLowerCase().includes(query) || String(source.hostId) === query) &&
        source.requests >= (filters.minimum || 1) &&
        (!filters.fingerprint || source.fingerprint === filters.fingerprint) &&
        (!filters.family || source.families.includes(filters.family)) &&
        (!filters.service || (filters.service === NO_OBSERVATIONS
            ? !source.services.length : source.services.includes(filters.service))));
}
