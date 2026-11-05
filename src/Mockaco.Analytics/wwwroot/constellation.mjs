export const familyColors = {
    "Control panels": "#f28e2b", "Site discovery": "#4e79a7", "Authentication": "#76b7b2",
    "PHP endpoints": "#b07aa1", "WordPress": "#edc948", "Secrets & config": "#e15759",
    "APIs & applications": "#59a14f", "Device interfaces": "#9c755f",
    "Other paths": "#bab0ac", "Empty target": "#ff9da7"
};

export class Constellation {
    constructor(canvas, tooltip, onSelect) {
        this.canvas = canvas;
        this.context = canvas.getContext("2d");
        this.tooltip = tooltip;
        this.onSelect = onSelect;
        this.mode = "groups";
        this.spread = true;
        this.zoom = 1;
        this.panX = this.panY = 0;
        this.centerX = this.centerY = 0;
        this.rangeX = this.rangeY = 1;
        this.nodes = this.groups = this.sourceNodes = [];
        this.matched = new Set();
        this.neighbors = [];
        new ResizeObserver(() => this.resize()).observe(canvas);
        canvas.addEventListener("pointerdown", event => {
            this.pendingHover = null;
            this.tooltip.hidden = true;
            this.drag = { x: event.offsetX, y: event.offsetY, panX: this.panX, panY: this.panY, moved: false };
            canvas.setPointerCapture(event.pointerId);
        });
        canvas.addEventListener("pointermove", event => {
            if (this.drag) {
                const dx = event.offsetX - this.drag.x;
                const dy = event.offsetY - this.drag.y;
                this.drag.moved ||= Math.hypot(dx, dy) > 4;
                if (this.drag.moved) {
                    this.panX = this.drag.panX + dx;
                    this.panY = this.drag.panY + dy;
                    this.tooltip.hidden = true;
                    this.queue();
                }
            } else {
                this.pendingHover = [event.offsetX, event.offsetY];
                this.queue(false);
            }
        });
        canvas.addEventListener("pointerup", event => {
            if (this.drag && !this.drag.moved) {
                const node = this.hit(event.offsetX, event.offsetY);
                if (node) this.onSelect(node);
            }
            this.drag = null;
            if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
        });
        canvas.addEventListener("pointercancel", () => { this.drag = null; });
        canvas.addEventListener("pointerleave", () => {
            this.pendingHover = null;
            this.tooltip.hidden = true;
        });
        canvas.addEventListener("wheel", event => {
            event.preventDefault();
            this.scale(Math.exp(-event.deltaY * .0015), event.offsetX, event.offsetY);
        }, { passive: false });
        canvas.addEventListener("keydown", event => {
            const deltas = { ArrowLeft: [35, 0], ArrowRight: [-35, 0], ArrowUp: [0, 35], ArrowDown: [0, -35] };
            if (deltas[event.key]) {
                event.preventDefault();
                this.pan(...deltas[event.key]);
            } else if (["+", "=", "-"].includes(event.key)) {
                event.preventDefault();
                this.scale(event.key === "-" ? .8 : 1.25);
            } else if (event.key === "Home") { event.preventDefault(); this.fit(); }
        });
    }

    setData(sources, reset = true) {
        const groups = new Map();
        this.sourceNodes = sources.map(source => ({
            id: source.hostId, kind: "source", x: source.x, y: source.y, sources: [source],
            label: source.ipAddress, family: source.dominantFamily, weight: source.requests
        }));
        for (const source of sources) {
            if (!groups.has(source.fingerprint))
                groups.set(source.fingerprint, { id: source.fingerprint, kind: "fingerprint",
                    x: 0, y: 0, sources: [], label: source.fingerprintLabel, family: source.dominantFamily });
            const group = groups.get(source.fingerprint);
            group.x += source.x;
            group.y += source.y;
            group.sources.push(source);
        }
        this.groups = [...groups.values()];
        for (const group of this.groups) {
            group.x /= group.sources.length;
            group.y /= group.sources.length;
            group.weight = group.sources.length;
        }
        this.prepare();
        if (reset) this.fit();
    }

    prepare() {
        this.hovered = this.pendingHover = null;
        this.tooltip.hidden = true;
        this.nodes = this.mode === "groups" ? this.groups : this.sourceNodes;
        const overlaps = new Map();
        for (const node of this.nodes) {
            const key = `${node.x.toFixed(6)},${node.y.toFixed(6)}`;
            if (!overlaps.has(key)) overlaps.set(key, []);
            overlaps.get(key).push(node);
        }
        for (const coincident of overlaps.values()) {
            coincident.forEach((node, index) => {
                const radius = this.spread && coincident.length > 1
                    ? Math.sqrt((index + .5) / coincident.length) * Math.min(.09, .004 * Math.sqrt(coincident.length)) : 0;
                node.px = node.x + Math.cos(index * 2.399963) * radius;
                node.py = node.y + Math.sin(index * 2.399963) * radius;
                node.radius = this.mode === "groups" ? 2.5 + Math.log2(node.weight + 1) * 1.15
                    : 1.8 + Math.log10(node.weight + 1) * .65;
            });
        }
        let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
        for (const node of this.nodes) {
            minX = Math.min(minX, node.px); maxX = Math.max(maxX, node.px);
            minY = Math.min(minY, node.py); maxY = Math.max(maxY, node.py);
        }
        this.centerX = this.nodes.length ? (minX + maxX) / 2 : 0;
        this.centerY = this.nodes.length ? (minY + maxY) / 2 : 0;
        this.rangeX = Math.max(.35, this.nodes.length ? maxX - minX : 1);
        this.rangeY = Math.max(.35, this.nodes.length ? maxY - minY : 1);
        this.updateActive();
    }

    setMode(mode) { this.mode = mode; this.prepare(); this.fit(); }
    setSpread(spread) { this.spread = spread; this.prepare(); }
    setSelection(matched, selectedId, neighbors = []) {
        this.matched = new Set(matched.map(source => source.hostId));
        this.selectedId = selectedId;
        this.neighbors = neighbors;
        this.updateActive();
    }
    updateActive() {
        for (const node of this.nodes) {
            node.matches = node.sources.reduce((count, source) => count + Number(this.matched.has(source.hostId)), 0);
            node.selected = node.sources.some(source => source.hostId === this.selectedId);
        }
        this.queue();
    }
    resize() {
        const { width, height } = this.canvas.getBoundingClientRect();
        const ratio = window.devicePixelRatio || 1;
        this.width = width; this.height = height;
        this.canvas.width = Math.round(width * ratio);
        this.canvas.height = Math.round(height * ratio);
        this.context.setTransform(ratio, 0, 0, ratio, 0, 0);
        this.queue();
    }
    fit() {
        this.zoom = 1; this.panX = this.panY = 0;
        this.pendingHover = null; this.tooltip.hidden = true;
        this.queue();
    }
    pan(x, y) {
        this.panX += x; this.panY += y;
        this.pendingHover = null; this.tooltip.hidden = true;
        this.queue();
    }
    scale(factor, x = this.width / 2, y = this.height / 2) {
        const next = Math.max(.25, Math.min(60, this.zoom * factor));
        factor = next / this.zoom;
        this.panX = x - this.width / 2 - (x - this.width / 2 - this.panX) * factor;
        this.panY = y - this.height / 2 - (y - this.height / 2 - this.panY) * factor;
        this.zoom = next;
        this.pendingHover = null;
        this.tooltip.hidden = true;
        this.queue();
    }
    position(node) {
        const base = Math.min((this.width - 100) / this.rangeX, (this.height - 100) / this.rangeY);
        return [this.width / 2 + (node.px - this.centerX) * base * this.zoom + this.panX,
            this.height / 2 - (node.py - this.centerY) * base * this.zoom + this.panY];
    }
    hit(x, y) {
        let nearest = null, distance = Infinity;
        for (const node of this.nodes) {
            if (!node.matches) continue;
            const [nx, ny] = this.position(node);
            const d = Math.hypot(nx - x, ny - y);
            if (d < Math.max(7, node.radius + 3) && d < distance) { nearest = node; distance = d; }
        }
        return nearest;
    }
    hover(x, y) {
        const node = this.hit(x, y);
        this.canvas.style.cursor = node ? "pointer" : "grab";
        this.tooltip.hidden = !node;
        if (!node) return;
        if (this.hovered !== node) this.tooltip.textContent = `${node.label}\n${node.kind === "fingerprint"
            ? `${node.sources.length.toLocaleString()} sources share this route/method set`
            : `${node.weight.toLocaleString()} requests / ${node.sources[0].pathCount} route-method pairs`}\n${node.family}`;
        this.hovered = node;
        const { offsetWidth, offsetHeight } = this.tooltip;
        this.tooltip.style.left = `${Math.max(8, Math.min(x + 16, this.width - offsetWidth - 8))}px`;
        this.tooltip.style.top = `${Math.max(8, Math.min(y + 16, this.height - offsetHeight - 8))}px`;
    }
    queue(redraw = true) {
        this.needsDraw ||= redraw;
        if (this.queued) return;
        this.queued = true;
        requestAnimationFrame(() => {
            this.queued = false;
            const redraw = this.needsDraw;
            this.needsDraw = false;
            if (redraw) this.draw();
            if (this.pendingHover) {
                const position = this.pendingHover;
                this.pendingHover = null;
                this.hover(...position);
            }
        });
    }
    draw() {
        const ctx = this.context;
        const w = this.width || 0, h = this.height || 0;
        ctx.clearRect(0, 0, w, h);
        if (!w || !h) return;
        ctx.strokeStyle = "#354d664d";
        ctx.lineWidth = 1;
        const zero = this.position({ px: 0, py: 0 });
        ctx.beginPath(); ctx.moveTo(zero[0], 0); ctx.lineTo(zero[0], h);
        ctx.moveTo(0, zero[1]); ctx.lineTo(w, zero[1]); ctx.stroke();
        const selected = this.nodes.find(node => node.selected);
        if (selected) {
            const start = this.position(selected);
            ctx.strokeStyle = "#76b7b270";
            for (const neighbor of this.neighbors) {
                const target = this.nodes.find(node => node.sources.some(source => source.hostId === neighbor.hostId));
                if (!target || target === selected || !target.matches) continue;
                const end = this.position(target);
                ctx.beginPath(); ctx.moveTo(...start); ctx.lineTo(...end); ctx.stroke();
            }
        }
        for (const active of [false, true]) {
            for (const node of this.nodes) {
                if (Boolean(node.matches) !== active) continue;
                const [x, y] = this.position(node);
                if (x < -25 || x > w + 25 || y < -25 || y > h + 25) continue;
                ctx.fillStyle = active ? familyColors[node.family] || "#bab0ac" : "#31465c";
                ctx.globalAlpha = active ? .83 : .32;
                ctx.beginPath(); ctx.arc(x, y, node.radius, 0, Math.PI * 2); ctx.fill();
                if (active && this.mode === "groups" && node.sources.length > 1) {
                    ctx.globalAlpha = .65;
                    ctx.strokeStyle = familyColors[node.family] || "#bab0ac";
                    ctx.beginPath(); ctx.arc(x, y, node.radius + 3, 0, Math.PI * 2); ctx.stroke();
                }
            }
        }
        ctx.globalAlpha = 1;
        if (selected) {
            const [x, y] = this.position(selected);
            const radius = selected.radius + 7;
            ctx.strokeStyle = "#f0f3f5"; ctx.lineWidth = 1;
            ctx.beginPath(); ctx.arc(x, y, radius, 0, Math.PI * 2); ctx.stroke();
            ctx.beginPath();
            ctx.moveTo(x - radius - 7, y); ctx.lineTo(x - radius + 2, y);
            ctx.moveTo(x + radius - 2, y); ctx.lineTo(x + radius + 7, y);
            ctx.moveTo(x, y - radius - 7); ctx.lineTo(x, y - radius + 2);
            ctx.moveTo(x, y + radius - 2); ctx.lineTo(x, y + radius + 7); ctx.stroke();
        }
        ctx.font = '12px "Consolas", monospace';
        ctx.fillStyle = "#afbdcb";
        ctx.fillText(`${this.nodes.length.toLocaleString()} ${this.mode === "groups" ? "fingerprints" : "sources"} / ${this.zoom.toFixed(1)}x`, 18, h - 16);
    }
}
