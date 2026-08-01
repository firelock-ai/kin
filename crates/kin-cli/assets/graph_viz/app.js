(function () {
  "use strict";

  const KIND_COLORS = {
    Function: "#7ee787",
    Class: "#79c0ff",
    Method: "#d2a8ff",
    Module: "#ffa657",
    EnumDef: "#8b949e",
    EnumVariant: "#8b949e",
    Constant: "#8b949e",
  };
  const DEFAULT_COLOR = "#8b949e";

  const EDGE_COLOR = "#6e7681";
  // Per-edge-kind colors. Chosen to be visually distinct against the dark
  // #0b0e14 background and against each other at 0.45 alpha. Kept
  // perceptually distinct from the node palette above so edges and nodes
  // don't blur together.
  const EDGE_KIND_COLORS = {
    Calls: "#f78166",      // warm orange-red — dominant relation
    Contains: "#58a6ff",   // cool blue — structural
    Imports: "#bf8dff",    // violet — cross-module
    Tests: "#3fb950",      // green — validation
    Extends: "#f2cc60",    // yellow — inheritance (rare, must pop)
  };
  const EDGE_ALPHA = 0.55;
  const DIM_ALPHA = 0.08;
  const EDGE_LINE_WIDTH = 1.0;
  const ORPHAN_ALPHA = 0.25;

  function edgeColor(kind) {
    return EDGE_KIND_COLORS[kind] || EDGE_COLOR;
  }

  const canvas = document.getElementById("graph");
  const ctx = canvas.getContext("2d");
  const tooltipEl = document.getElementById("tooltip");
  const statusEl = document.getElementById("status");
  const nodeCountEl = document.getElementById("node-count");
  const edgeCountEl = document.getElementById("edge-count");

  // The layout engine is loaded from a CDN, so a machine with no network
  // reaches this file with `d3` undefined. Say so in the page instead of
  // throwing on the first `d3.` reference and leaving a blank canvas that looks
  // like an empty graph.
  if (typeof d3 === "undefined") {
    statusEl.textContent =
      "the layout engine (d3) could not be loaded from the network; " +
      "kin graph viz needs network access to render";
    statusEl.classList.add("error");
    statusEl.classList.remove("hidden");
    return;
  }

  let width = 0;
  let height = 0;
  let dpr = window.devicePixelRatio || 1;

  let nodes = [];
  let links = [];
  // Relations the graph reported whose other endpoint is no node here. Kept so
  // the resting page still says the drawing is partial rather than implying
  // every relation is on screen.
  let withheldRelations = 0;
  let neighbors = new Map();
  let quadtree = null;

  let transform = d3.zoomIdentity;
  let hoverNode = null;
  let pinnedNode = null;

  function nodeRadius(d) {
    const deg = Math.max(0, d.degree || 0);
    return Math.max(3, Math.min(18, 3 + Math.sqrt(deg)));
  }

  function nodeColor(d) {
    return KIND_COLORS[d.kind] || DEFAULT_COLOR;
  }

  function resize() {
    dpr = window.devicePixelRatio || 1;
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.width = width + "px";
    canvas.style.height = height + "px";
    draw();
  }

  function setStatus(text, isError) {
    if (!text) {
      statusEl.classList.add("hidden");
      return;
    }
    statusEl.textContent = text;
    statusEl.classList.toggle("error", !!isError);
    statusEl.classList.remove("hidden");
  }

  function buildNeighbors(ns, ls) {
    const map = new Map();
    for (const n of ns) map.set(n.id, new Set());
    for (const l of ls) {
      const s = typeof l.source === "object" ? l.source.id : l.source;
      const t = typeof l.target === "object" ? l.target.id : l.target;
      if (map.has(s) && map.has(t)) {
        map.get(s).add(t);
        map.get(t).add(s);
      }
    }
    return map;
  }

  function activeNode() {
    return pinnedNode || hoverNode;
  }

  function isHighlighted(node) {
    const a = activeNode();
    if (!a) return true;
    if (node === a) return true;
    const nbrs = neighbors.get(a.id);
    return nbrs ? nbrs.has(node.id) : false;
  }

  function isLinkHighlighted(link) {
    const a = activeNode();
    if (!a) return true;
    return link.source === a || link.target === a;
  }

  function draw() {
    if (!ctx) return;
    ctx.save();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    ctx.translate(transform.x, transform.y);
    ctx.scale(transform.k, transform.k);

    const hasActive = !!activeNode();

    ctx.lineWidth = EDGE_LINE_WIDTH / transform.k;
    ctx.globalAlpha = EDGE_ALPHA;

    if (!hasActive) {
      // Group by kind so we only swap strokeStyle once per kind.
      const byKind = new Map();
      for (const l of links) {
        const s = l.source;
        const t = l.target;
        if (!s || !t || typeof s.x !== "number" || typeof t.x !== "number") continue;
        const key = l.kind || "";
        let arr = byKind.get(key);
        if (!arr) {
          arr = [];
          byKind.set(key, arr);
        }
        arr.push(l);
      }
      for (const [kind, arr] of byKind) {
        ctx.strokeStyle = edgeColor(kind);
        ctx.beginPath();
        for (const l of arr) {
          ctx.moveTo(l.source.x, l.source.y);
          ctx.lineTo(l.target.x, l.target.y);
        }
        ctx.stroke();
      }
    } else {
      ctx.globalAlpha = DIM_ALPHA;
      ctx.strokeStyle = EDGE_COLOR;
      ctx.beginPath();
      for (const l of links) {
        if (isLinkHighlighted(l)) continue;
        const s = l.source;
        const t = l.target;
        if (!s || !t || typeof s.x !== "number" || typeof t.x !== "number") continue;
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(t.x, t.y);
      }
      ctx.stroke();

      ctx.globalAlpha = 0.75;
      ctx.strokeStyle = "#58a6ff";
      ctx.beginPath();
      for (const l of links) {
        if (!isLinkHighlighted(l)) continue;
        const s = l.source;
        const t = l.target;
        if (!s || !t || typeof s.x !== "number" || typeof t.x !== "number") continue;
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(t.x, t.y);
      }
      ctx.stroke();
    }

    for (const n of nodes) {
      if (typeof n.x !== "number") continue;
      const highlighted = isHighlighted(n);
      const isOrphan = (n.degree || 0) === 0;
      const base = isOrphan ? ORPHAN_ALPHA : 1;
      ctx.globalAlpha = hasActive ? (highlighted ? 1 : DIM_ALPHA) : base;
      const r = nodeRadius(n);
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.fillStyle = nodeColor(n);
      ctx.fill();
      if (hasActive && n === activeNode()) {
        ctx.lineWidth = 1.5 / transform.k;
        ctx.strokeStyle = "#e6edf3";
        ctx.stroke();
      }
    }

    ctx.globalAlpha = 1;
    ctx.restore();
  }

  function screenToWorld(px, py) {
    return [(px - transform.x) / transform.k, (py - transform.y) / transform.k];
  }

  function findNodeAt(px, py) {
    if (!quadtree) return null;
    const [wx, wy] = screenToWorld(px, py);
    const searchRadius = 12 / transform.k;
    const found = quadtree.find(wx, wy, searchRadius);
    if (!found) return null;
    const dx = found.x - wx;
    const dy = found.y - wy;
    const dist = Math.sqrt(dx * dx + dy * dy);
    const hitRadius = Math.max(nodeRadius(found), 6 / transform.k);
    return dist <= hitRadius ? found : null;
  }

  function showTooltip(node, clientX, clientY) {
    if (!node) {
      tooltipEl.hidden = true;
      return;
    }
    tooltipEl.querySelector(".t-name").textContent = node.name || node.id;
    tooltipEl.querySelector(".t-kind").textContent = node.kind || "";
    const fileEl = tooltipEl.querySelector(".t-file");
    if (node.file) {
      fileEl.textContent = node.file;
      fileEl.style.display = "";
    } else {
      fileEl.textContent = "";
      fileEl.style.display = "none";
    }
    tooltipEl.querySelector(".t-degree").textContent =
      "degree " + (node.degree != null ? node.degree : 0);

    tooltipEl.hidden = false;
    const rect = tooltipEl.getBoundingClientRect();
    let x = clientX + 14;
    let y = clientY + 14;
    if (x + rect.width > width - 8) x = clientX - rect.width - 14;
    if (y + rect.height > height - 8) y = clientY - rect.height - 14;
    if (x < 8) x = 8;
    if (y < 8) y = 8;
    tooltipEl.style.left = x + "px";
    tooltipEl.style.top = y + "px";
  }

  function onMouseMove(ev) {
    const rect = canvas.getBoundingClientRect();
    const px = ev.clientX - rect.left;
    const py = ev.clientY - rect.top;
    const node = findNodeAt(px, py);
    const prev = hoverNode;
    hoverNode = node;
    if (node) {
      showTooltip(node, ev.clientX, ev.clientY);
      canvas.style.cursor = "pointer";
    } else {
      tooltipEl.hidden = true;
      canvas.style.cursor = "";
    }
    if (prev !== node) draw();
  }

  function onMouseLeave() {
    hoverNode = null;
    tooltipEl.hidden = true;
    draw();
  }

  function onClick(ev) {
    const rect = canvas.getBoundingClientRect();
    const px = ev.clientX - rect.left;
    const py = ev.clientY - rect.top;
    const node = findNodeAt(px, py);
    pinnedNode = node ? node : null;
    draw();
  }

  function attachZoom() {
    const zoom = d3
      .zoom()
      .scaleExtent([0.05, 12])
      .on("zoom", (event) => {
        transform = event.transform;
        draw();
      });
    d3.select(canvas).call(zoom);
  }

  function rebuildQuadtree() {
    quadtree = d3
      .quadtree()
      .x((d) => d.x)
      .y((d) => d.y)
      .addAll(nodes);
  }

  function partialNote() {
    if (withheldRelations <= 0) return "";
    return (
      " (" +
      withheldRelations.toLocaleString() +
      " relation(s) point outside this graph and are not drawn)"
    );
  }

  async function load() {
    setStatus("loading graph...");
    let data;
    try {
      const res = await fetch("/api/graph.json");
      if (!res.ok) throw new Error("HTTP " + res.status);
      data = await res.json();
    } catch (err) {
      setStatus("failed to load graph: " + err.message, true);
      return;
    }

    nodes = (data.nodes || []).map((n) => Object.assign({}, n));

    // The force layout resolves every link endpoint against the node set and
    // throws on the first id it cannot find, which aborts the whole render.
    // The server already withholds those links; drop any that survive anyway
    // rather than letting one dangling endpoint blank the canvas.
    const nodeIds = new Set(nodes.map((n) => n.id));
    const raw = data.links || [];
    links = raw
      .filter((l) => nodeIds.has(l.source) && nodeIds.has(l.target))
      .map((l) => Object.assign({}, l));
    const droppedHere = raw.length - links.length;
    withheldRelations = (data.unresolved_links || 0) + droppedHere;

    nodeCountEl.textContent = nodes.length.toLocaleString();
    edgeCountEl.textContent = links.length.toLocaleString();

    if (nodes.length === 0) {
      setStatus("graph is empty", false);
      draw();
      return;
    }

    setStatus(
      "laying out " + nodes.length.toLocaleString() + " nodes..." + partialNote()
    );

    const cx = width / 2;
    const cy = height / 2;
    // Scale repulsion and initial spread with node count so layouts don't clump
    // on large graphs or explode on small ones.
    const n = nodes.length;
    const chargeStrength = -Math.max(60, Math.min(400, 40 + n * 0.12));
    const linkDistance = n > 600 ? 60 : n > 200 ? 45 : 35;
    const spreadRadius = Math.min(width, height) * 0.45;
    for (const node of nodes) {
      const a = Math.random() * Math.PI * 2;
      const r = Math.sqrt(Math.random()) * spreadRadius;
      node.x = cx + Math.cos(a) * r;
      node.y = cy + Math.sin(a) * r;
    }

    const simulation = d3
      .forceSimulation(nodes)
      .force(
        "charge",
        d3.forceManyBody().strength(chargeStrength).distanceMax(Math.max(width, height) * 0.6)
      )
      .force(
        "link",
        d3
          .forceLink(links)
          .id((d) => d.id)
          .distance(linkDistance)
          .strength(0.25)
      )
      .force("center", d3.forceCenter(cx, cy).strength(0.04))
      .force("x", d3.forceX(cx).strength(0.015))
      .force("y", d3.forceY(cy).strength(0.015))
      .force(
        "collide",
        d3.forceCollide().radius((d) => nodeRadius(d) + 2)
      )
      .alpha(1)
      .alphaDecay(1 - Math.pow(0.001, 1 / 500));

    neighbors = buildNeighbors(nodes, links);

    let tick = 0;
    simulation.on("tick", () => {
      tick++;
      if (tick % 2 === 0) {
        rebuildQuadtree();
        draw();
      }
    });

    simulation.on("end", () => {
      rebuildQuadtree();
      draw();
      setStatus(partialNote().trim());
    });

    setTimeout(() => {
      if (simulation.alpha() > 0) {
        simulation.alpha(0).stop();
        rebuildQuadtree();
        draw();
        setStatus(partialNote().trim());
      }
    }, 20000);
  }

  canvas.addEventListener("mousemove", onMouseMove);
  canvas.addEventListener("mouseleave", onMouseLeave);
  canvas.addEventListener("click", onClick);
  window.addEventListener("resize", resize);

  resize();
  attachZoom();
  load();
})();
