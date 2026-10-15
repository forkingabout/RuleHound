"use strict";

const PREBUILT_QUERIES = [
    {
        name: "All objects",
        query: "MATCH (n) WHERE n.id <> 0 RETURN n LIMIT 1000",
    },
    {
        name: "Firewall rules and what they reference",
        query: "MATCH p = (r:FirewallRule)-->() RETURN p",
    },
    {
        name: "Most-referenced objects",
        query: "MATCH (n)<--(m) WITH n, count(m) AS refs ORDER BY refs DESC LIMIT 25\nMATCH (n)<--(m) RETURN n, m",
    },
    {
        name: "Unlinked objects",
        query: "MATCH (n) WHERE n.id <> 0 AND NOT (n)--() RETURN n",
    },
];

const DEFAULT_QUERY = PREBUILT_QUERIES[0].query;

const PALETTE = [
    "#5fa8e8", "#f2b544", "#5cc28d", "#e0645c", "#b48ae6",
    "#4fc6c4", "#e88fbf", "#c9cf5b", "#f08a4b", "#8fa3ff",
];

const UPLOAD_CONTENT_TYPE = "application/yaml; charset=utf-8";

const SELECTION_HINT = "Click an object or link to inspect it. Double-click an object to pull in its neighbours.";

const el = {
    query: document.getElementById("query"),
    run: document.getElementById("run"),
    cancel: document.getElementById("cancel"),
    prebuilt: document.getElementById("prebuilt"),
    search: document.getElementById("search"),
    layout: document.getElementById("layout"),
    fit: document.getElementById("fit"),
    uploadButton: document.getElementById("upload-button"),
    upload: document.getElementById("upload"),
    clearButton: document.getElementById("clear-button"),
    detailsTitle: document.getElementById("details-title"),
    detailsContent: document.getElementById("details-content"),
    legend: document.getElementById("legend"),
    empty: document.getElementById("empty"),
    emptyMessage: document.getElementById("empty-message"),
    loading: document.getElementById("loading"),
    status: document.getElementById("status"),
    meta: document.getElementById("meta"),
    counts: document.getElementById("counts"),
};

const hiddenTypes = new Set();

// AbortController for the query currently in flight, if any.
let activeQuery = null;
const typeColors = new Map();

// ---------------------------------------------------------------------------
// Cytoscape setup
// ---------------------------------------------------------------------------

let hasFcose = false;

if (typeof cytoscapeFcose !== "undefined") {
    try {
        cytoscape.use(cytoscapeFcose);
    } catch (_) {
        // Already registered by the UMD bundle.
    }
    hasFcose = true;
}

const cy = cytoscape({
    container: document.getElementById("cy"),
    minZoom: 0.05,
    maxZoom: 4,
    style: [
        {
            selector: "node",
            style: {
                "background-color": "data(color)",
                "label": "data(label)",
                "color": "#dbe4ee",
                "font-family": "IBM Plex Sans, Segoe UI, sans-serif",
                "font-size": 10,
                "text-valign": "bottom",
                "text-margin-y": 5,
                "text-outline-color": "#14202e",
                "text-outline-width": 2,
                "text-max-width": 140,
                "text-wrap": "ellipsis",
                "width": 26,
                "height": 26,
                "border-width": 2,
                "border-color": "#14202e",
            },
        },
        {
            selector: "edge",
            style: {
                "width": 1.5,
                "line-color": "#46607d",
                "target-arrow-color": "#46607d",
                "target-arrow-shape": "triangle",
                "arrow-scale": 0.9,
                "curve-style": "bezier",
                "label": "data(type)",
                "font-family": "IBM Plex Mono, Consolas, monospace",
                "font-size": 8,
                "color": "#8a9bb0",
                "text-rotation": "autorotate",
                "text-outline-color": "#14202e",
                "text-outline-width": 2,
                "min-zoomed-font-size": 7,
            },
        },
        {
            selector: "node:selected",
            style: {
                "border-color": "#f2b544",
                "border-width": 4,
            },
        },
        {
            selector: "edge:selected",
            style: {
                "line-color": "#f2b544",
                "target-arrow-color": "#f2b544",
                "color": "#f2b544",
                "width": 3,
            },
        },
        {
            selector: "node.match",
            style: {
                "border-color": "#ffffff",
                "border-width": 4,
            },
        },
        {
            selector: "edge.highlight",
            style: {
                "line-color": "#f2b544",
                "target-arrow-color": "#f2b544",
                "color": "#dbe4ee",
                "width": 2.5,
            },
        },
        {
            selector: ".faded",
            style: {
                "opacity": 0.15,
            },
        },
        {
            selector: ".type-hidden",
            style: {
                "display": "none",
            },
        },
    ],
});

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

async function fetchQuery(cypher, signal) {
    const response = await fetch("/api/query/json", {
        method: "POST",
        headers: { "Content-Type": "text/plain; charset=utf-8" },
        body: cypher,
        signal,
    });

    if (!response.ok) {
        const text = (await response.text()).trim();
        throw new Error(text || `Query failed with HTTP ${response.status}`);
    }

    return response.json();
}

async function ingestYAML(text) {
    const response = await fetch("/api/ingest/yaml", {
        method: "POST",
        headers: { "Content-Type": UPLOAD_CONTENT_TYPE },
        body: text,
    });

    const message = (await response.text()).trim();

    if (!response.ok) {
        throw new Error(message || `Upload failed with HTTP ${response.status}`);
    }

    return message;
}

async function clearDatabase() {
    const response = await fetch("/api/clear", { method: "POST" });
    const message = (await response.text()).trim();

    if (!response.ok) {
        throw new Error(message || `Clear failed with HTTP ${response.status}`);
    }

    return message;
}

// ---------------------------------------------------------------------------
// Conversion
// ---------------------------------------------------------------------------

function colorFor(type) {
    if (!typeColors.has(type)) {
        typeColors.set(type, PALETTE[typeColors.size % PALETTE.length]);
    }
    return typeColors.get(type);
}

// Caption names the property whose value is used as the label.
function labelFor(node) {
    const properties = node.properties || {};
    const key = node.caption;

    if (key && Object.prototype.hasOwnProperty.call(properties, key)) {
        const value = properties[key];

        if (value !== null && value !== undefined && value !== "") {
            return typeof value === "object" ? JSON.stringify(value) : String(value);
        }
    }

    // Caption missing, or it names a property the object doesn't have.
    return `${node.type || "Unknown"} ${node.id}`;
}

function toElements(doc) {
    const elements = [];

    for (const node of doc.nodes) {
        elements.push({
            group: "nodes",
            data: {
                id: String(node.id),
                rhId: node.id,
                type: node.type || "Unknown",
                caption: node.caption || "",
                label: labelFor(node),
                color: colorFor(node.type || "Unknown"),
                properties: node.properties || {},
            },
        });
    }

    // Multiple relationships of the same type between the same pair get
    // distinct, stable IDs so merges don't duplicate them.
    const seen = new Map();

    for (const link of doc.links) {
        const type = link.type || "LINKS_TO";
        const key = `${link.from}-${type}-${link.to}`;
        const index = seen.get(key) || 0;
        seen.set(key, index + 1);

        elements.push({
            group: "edges",
            data: {
                id: `e${key}-${index}`,
                source: String(link.from),
                target: String(link.to),
                type,
                properties: link.properties || {},
            },
        });
    }

    return elements;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function prefersReducedMotion() {
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function layoutOptions(name, randomize) {
    switch (name) {
        case "fcose":
            if (hasFcose) {
                return {
                    name: "fcose",
                    quality: "default",
                    randomize,
                    animate: !prefersReducedMotion(),
                    animationDuration: 500,
                    nodeRepulsion: 6500,
                    idealEdgeLength: 90,
                    nodeSeparation: 60,
                    packComponents: true,
                };
            }
            return {
                name: "cose",
                randomize,
                animate: false,
                nodeRepulsion: 8000,
                idealEdgeLength: 90,
            };
        case "breadthfirst":
            return { name: "breadthfirst", directed: true, spacingFactor: 1.3, animate: false };
        case "concentric":
            return {
                name: "concentric",
                concentric: (node) => node.degree(),
                levelWidth: () => 2,
                minNodeSpacing: 30,
                animate: false,
            };
        case "circle":
            return { name: "circle", animate: false };
        default:
            return { name: "grid", animate: false };
    }
}

function runLayout(randomize = true) {
    const visible = cy.elements().not(".type-hidden");

    if (visible.empty()) {
        return;
    }

    visible.layout(layoutOptions(el.layout.value, randomize)).run();
}

function render(doc, { merge = false, anchor = null } = {}) {
    const elements = toElements(doc);

    cy.batch(() => {
        if (!merge) {
            cy.elements().remove();
            clearDetails();
        }

        const fresh = elements.filter((e) => cy.getElementById(e.data.id).empty());

        // Start new neighbours on top of the node they were expanded from.
        if (anchor) {
            const position = anchor.position();
            for (const e of fresh) {
                if (e.group === "nodes") {
                    e.position = { x: position.x, y: position.y };
                }
            }
        }

        cy.add(fresh);
        applyTypeVisibility();
    });

    updateMeta(doc.meta);
    updateCounts();
    updateLegend();
    updateEmptyState();
    applySearch();

    runLayout(!merge);

    if (!merge) {
        cy.fit(undefined, 40);
    }
}

function updateMeta(meta) {
    if (!meta) {
        return;
    }

    const parts = [];

    if (meta.firewallBrand) {
        const versions = (meta.firewallVersions || []).join(", ");
        parts.push(versions ? `${meta.firewallBrand} ${versions}` : meta.firewallBrand);
    }

    if (meta.parserName) {
        parts.push(meta.parserVersion ? `${meta.parserName} ${meta.parserVersion}` : meta.parserName);
    }

    el.meta.textContent = parts.join(", parsed by ");
}

function updateCounts() {
    const nodes = cy.nodes().length;
    const links = cy.edges().length;
    el.counts.textContent = `${nodes} ${nodes === 1 ? "object" : "objects"}, ${links} ${links === 1 ? "link" : "links"}`;
}

function updateEmptyState(message) {
    const isEmpty = cy.nodes().empty();
    el.empty.hidden = !isEmpty;
    if (isEmpty) {
        el.emptyMessage.textContent = message || "No objects matched this query. Pick a pre-built query or upload a YAML file.";
    }
}

function updateLegend() {
    const counts = new Map();

    cy.nodes().forEach((node) => {
        const type = node.data("type");
        counts.set(type, (counts.get(type) || 0) + 1);
    });

    el.legend.replaceChildren();
    el.legend.hidden = counts.size === 0;

    const types = [...counts.keys()].sort();

    for (const type of types) {
        const button = document.createElement("button");
        button.type = "button";
        button.title = hiddenTypes.has(type) ? `Show ${type}` : `Hide ${type}`;
        button.classList.toggle("off", hiddenTypes.has(type));

        const swatch = document.createElement("span");
        swatch.className = "swatch";
        swatch.style.background = colorFor(type);

        const name = document.createElement("span");
        name.textContent = type;

        const count = document.createElement("span");
        count.className = "count";
        count.textContent = counts.get(type);

        button.append(swatch, name, count);

        button.addEventListener("click", () => {
            if (hiddenTypes.has(type)) {
                hiddenTypes.delete(type);
            } else {
                hiddenTypes.add(type);
            }
            applyTypeVisibility();
            updateLegend();
        });

        el.legend.append(button);
    }
}

function applyTypeVisibility() {
    cy.nodes().forEach((node) => {
        node.toggleClass("type-hidden", hiddenTypes.has(node.data("type")));
    });
}

// ---------------------------------------------------------------------------
// Details panel
// ---------------------------------------------------------------------------

function clearDetails() {
    el.detailsTitle.textContent = "Nothing selected";

    const hint = document.createElement("p");
    hint.className = "hint";
    hint.textContent = SELECTION_HINT;

    el.detailsContent.replaceChildren(hint);
}

function formatValue(value) {
    if (value === null || value === undefined) {
        return "";
    }
    if (typeof value === "object") {
        return JSON.stringify(value, null, 2);
    }
    return String(value);
}

function propertyList(entries) {
    const list = document.createElement("dl");
    list.className = "props";

    for (const [key, value] of entries) {
        const dt = document.createElement("dt");
        dt.textContent = key;

        const dd = document.createElement("dd");
        dd.textContent = formatValue(value);

        list.append(dt, dd);
    }

    return list;
}

function sortedProperties(properties) {
    return Object.entries(properties || {}).sort(([a], [b]) => a.localeCompare(b));
}

function sectionTitle(text) {
    const title = document.createElement("h3");
    title.className = "section-title";
    title.textContent = text;
    return title;
}

function typeTag(text, color) {
    const tag = document.createElement("div");
    tag.className = "type-tag";

    if (color) {
        const swatch = document.createElement("span");
        swatch.className = "swatch";
        swatch.style.background = color;
        tag.append(swatch);
    }

    const name = document.createElement("span");
    name.textContent = text;
    tag.append(name);

    return tag;
}

// A clickable row for an object, optionally tagged with a relationship type.
function nodeRow(node, relType) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";

    const swatch = document.createElement("span");
    swatch.className = "swatch";
    swatch.style.background = node.data("color");

    const label = document.createElement("span");
    label.className = "name";
    label.textContent = node.data("label");

    button.append(swatch);

    if (relType) {
        const rel = document.createElement("span");
        rel.className = "rel";
        rel.textContent = relType;
        button.append(rel);
    }

    const id = document.createElement("span");
    id.className = "id";
    id.textContent = node.data("rhId");

    button.append(label, id);
    button.addEventListener("click", () => {
        focusElement(node);
        showNodeDetails(node);
    });

    item.append(button);
    return item;
}

function relationshipList(edges, direction) {
    const list = document.createElement("ul");
    list.className = "link-list";

    edges.forEach((edge) => {
        const other = direction === "out" ? edge.target() : edge.source();
        list.append(nodeRow(other, edge.data("type")));
    });

    return list;
}

function showNodeDetails(node) {
    const data = node.data();

    el.detailsTitle.textContent = data.label;

    const children = [
        typeTag(data.type, data.color),
        propertyList([["ID", data.rhId], ["Label property", data.caption || "(none)"]]),
    ];

    const properties = sortedProperties(data.properties);

    if (properties.length > 0) {
        children.push(sectionTitle("Properties"), propertyList(properties));
    }

    const outgoing = node.connectedEdges().filter((edge) => edge.source().same(node));
    const incoming = node.connectedEdges().filter((edge) => edge.target().same(node));

    if (outgoing.length > 0) {
        children.push(sectionTitle(`Links to (${outgoing.length})`), relationshipList(outgoing, "out"));
    }

    if (incoming.length > 0) {
        children.push(sectionTitle(`Linked from (${incoming.length})`), relationshipList(incoming, "in"));
    }

    el.detailsContent.replaceChildren(...children);
}

function showEdgeDetails(edge) {
    const data = edge.data();

    el.detailsTitle.textContent = data.type;

    const from = document.createElement("ul");
    from.className = "link-list";
    from.append(nodeRow(edge.source()));

    const to = document.createElement("ul");
    to.className = "link-list";
    to.append(nodeRow(edge.target()));

    const children = [
        typeTag("Link"),
        sectionTitle("From"),
        from,
        sectionTitle("To"),
        to,
    ];

    const properties = sortedProperties(data.properties);

    if (properties.length > 0) {
        children.push(sectionTitle("Properties"), propertyList(properties));
    }

    el.detailsContent.replaceChildren(...children);
}

function focusElement(element) {
    cy.elements().unselect();
    element.select();
    cy.animate({
        center: { eles: element },
        zoom: Math.max(cy.zoom(), 1.2),
        duration: prefersReducedMotion() ? 0 : 300,
    });
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

function setStatus(message, kind = "") {
    el.status.textContent = message;
    el.status.className = kind;
}

// cancellable swaps Run for Cancel; uploads and clears are not cancellable
// because aborting them midway would leave a partially written graph.
function setBusy(busy, cancellable = false) {
    el.loading.hidden = !busy;
    el.run.disabled = busy;
    el.run.hidden = busy && cancellable;
    el.cancel.hidden = !(busy && cancellable);
    el.uploadButton.disabled = busy;
    el.clearButton.disabled = busy;
}

// Starts a cancellable query and returns its AbortController.
function beginQuery() {
    activeQuery = new AbortController();
    setBusy(true, true);
    return activeQuery;
}

// Only the query that is still current may reset the busy state, so a
// cancelled query finishing late can't unlock the UI under a newer one.
function endQuery(query) {
    if (activeQuery !== query) {
        return;
    }

    activeQuery = null;
    setBusy(false);
}

function cancelQuery() {
    if (activeQuery) {
        activeQuery.abort();
    }
}

function isAbort(err) {
    return err && err.name === "AbortError";
}

async function runQuery() {
    const cypher = el.query.value.trim();

    if (!cypher) {
        setStatus("Enter a Cypher query to run.", "error");
        return;
    }

    const query = beginQuery();
    setStatus("Running query");

    try {
        const doc = await fetchQuery(cypher, query.signal);
        render(doc);
        setStatus(`Query returned ${doc.nodes.length} objects and ${doc.links.length} links`, "ok");
    } catch (err) {
        if (isAbort(err)) {
            setStatus("Query cancelled. The graph still shows the previous result.");
            return;
        }

        setStatus(err.message, "error");

        if (cy.nodes().empty()) {
            updateEmptyState(`The query failed: ${err.message}`);
        }
    } finally {
        endQuery(query);
    }
}

async function expandNode(node) {
    const id = Number(node.data("rhId"));

    if (!Number.isInteger(id)) {
        return;
    }

    const query = beginQuery();
    setStatus(`Expanding ${node.data("label")}`);

    try {
        const doc = await fetchQuery(`MATCH (n {id: ${id}})--(m) RETURN n, m`, query.signal);
        const before = cy.nodes().length;

        render(doc, { merge: true, anchor: node });

        const added = cy.nodes().length - before;
        setStatus(
            added > 0 ? `Added ${added} neighbours of ${node.data("label")}` : `${node.data("label")} has no further neighbours`,
            "ok",
        );

        showNodeDetails(node);
    } catch (err) {
        if (isAbort(err)) {
            setStatus(`Cancelled expanding ${node.data("label")}`);
            return;
        }

        setStatus(err.message, "error");
    } finally {
        endQuery(query);
    }
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

function searchMatches() {
    const term = el.search.value.trim().toLowerCase();

    if (!term) {
        return cy.collection();
    }

    return cy.nodes().filter((node) => {
        const data = node.data();
        return (
            data.label.toLowerCase().includes(term) ||
            data.type.toLowerCase().includes(term) ||
            String(data.rhId) === term
        );
    });
}

function applySearch() {
    cy.nodes().removeClass("match");
    searchMatches().addClass("match");
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

cy.on("tap", "node", (event) => showNodeDetails(event.target));

cy.on("tap", "edge", (event) => showEdgeDetails(event.target));

cy.on("tap", (event) => {
    if (event.target === cy) {
        clearDetails();
    }
});

cy.on("dbltap", "node", (event) => {
    if (!activeQuery) {
        expandNode(event.target);
    }
});

cy.on("mouseover", "node", (event) => {
    const neighbourhood = event.target.closedNeighborhood();
    cy.elements().not(neighbourhood).addClass("faded");
    neighbourhood.edges().addClass("highlight");
});

cy.on("mouseover", "edge", (event) => {
    const edge = event.target;
    const involved = edge.union(edge.connectedNodes());
    cy.elements().not(involved).addClass("faded");
    edge.addClass("highlight");
});

cy.on("mouseout", "node, edge", () => {
    cy.elements().removeClass("faded highlight");
});

el.run.addEventListener("click", runQuery);

el.cancel.addEventListener("click", cancelQuery);

document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && activeQuery) {
        event.preventDefault();
        cancelQuery();
    }
});

el.query.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();

        if (!activeQuery) {
            runQuery();
        }
    }
});

function autosizeQuery() {
    el.query.style.height = "auto";
    el.query.style.height = `${Math.min(el.query.scrollHeight + 2, 160)}px`;
}

el.query.addEventListener("input", autosizeQuery);

for (const preset of PREBUILT_QUERIES) {
    const option = document.createElement("option");
    option.value = preset.query;
    option.textContent = preset.name;
    el.prebuilt.append(option);
}

el.prebuilt.addEventListener("change", () => {
    if (!el.prebuilt.value) {
        return;
    }
    el.query.value = el.prebuilt.value;
    el.prebuilt.value = "";
    autosizeQuery();
    cancelQuery();
    runQuery();
});

el.search.addEventListener("input", applySearch);

el.search.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") {
        return;
    }

    const matches = searchMatches().not(".type-hidden");

    if (matches.empty()) {
        setStatus(`Nothing in the graph matches "${el.search.value.trim()}"`, "error");
        return;
    }

    if (matches.length === 1) {
        focusElement(matches[0]);
        showNodeDetails(matches[0]);
    } else {
        cy.fit(matches, 60);
    }

    setStatus(`${matches.length} ${matches.length === 1 ? "match" : "matches"}`, "ok");
});

el.layout.addEventListener("change", () => runLayout(true));

el.fit.addEventListener("click", () => cy.fit(cy.elements().not(".type-hidden"), 40));

el.uploadButton.addEventListener("click", () => el.upload.click());

el.upload.addEventListener("change", async () => {
    const file = el.upload.files[0];
    el.upload.value = "";

    if (!file) {
        return;
    }

    setBusy(true);
    setStatus(`Uploading ${file.name}`);

    try {
        const message = await ingestYAML(await file.text());
        setStatus(`${file.name}: ${message}`, "ok");
        setBusy(false);
        await runQuery();
    } catch (err) {
        setStatus(`${file.name}: ${err.message}`, "error");
    } finally {
        setBusy(false);
    }
});

el.clearButton.addEventListener("click", async () => {
    const confirmed = window.confirm(
        "Delete every object and link from the database? This cannot be undone.",
    );

    if (!confirmed) {
        return;
    }

    setBusy(true);
    setStatus("Clearing database");

    try {
        await clearDatabase();

        cy.elements().remove();
        clearDetails();
        hiddenTypes.clear();
        typeColors.clear();

        el.meta.textContent = "";
        updateCounts();
        updateLegend();
        updateEmptyState("The database is empty. Upload a YAML file to load a firewall configuration.");

        setStatus("Database cleared", "ok");
    } catch (err) {
        setStatus(err.message, "error");
    } finally {
        setBusy(false);
    }
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

el.query.value = DEFAULT_QUERY;
autosizeQuery();
runQuery();