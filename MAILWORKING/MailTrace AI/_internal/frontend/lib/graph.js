/* MailTrace AI — forensic relationship graph.
   Canvas 2D force layout with depth cues: built only from real nodes/edges produced by the
   analysis engine (email → sender → domain → IP → ASN → location → URL → indicator). */
(function () {
  "use strict";

  var TYPE = {
    email:      { color: "#4de3d4", label: "Email", r: 13 },
    sender:     { color: "#59a8ff", label: "Sender", r: 10 },
    reply_to:   { color: "#ff9f43", label: "Reply-To", r: 9 },
    return_path:{ color: "#ffd166", label: "Return-Path", r: 8 },
    domain:     { color: "#a5b4fc", label: "Domain", r: 9 },
    url_domain: { color: "#ff9f43", label: "Link domain", r: 8 },
    ip:         { color: "#ff5f6d", label: "IP", r: 9 },
    asn:        { color: "#c084fc", label: "ASN", r: 8 },
    location:   { color: "#3ddc97", label: "Location", r: 9 },
    attachment: { color: "#fbbf24", label: "Attachment", r: 8 },
    wallet:     { color: "#f472b6", label: "Wallet", r: 7 },
    phone:      { color: "#94a3b8", label: "Phone", r: 6 },
    upi:        { color: "#7dd3fc", label: "UPI", r: 6 },
    campaign:   { color: "#f87171", label: "Campaign", r: 10 },
    mailbox:    { color: "#67e8f9", label: "Mailbox", r: 9 },
    /* indicator types emitted by the case store's correlation table */
    origin_ip:      { color: "#ff5f6d", label: "Origin IP", r: 9 },
    sender_domain:  { color: "#a5b4fc", label: "Sender domain", r: 9 },
    reply_to:       { color: "#ff9f43", label: "Reply-To", r: 9 },
    file_sha256:    { color: "#fbbf24", label: "File hash", r: 8 },
    crypto_wallet:  { color: "#f472b6", label: "Wallet", r: 7 },
    upi_id:         { color: "#7dd3fc", label: "UPI", r: 6 },
    phone:          { color: "#94a3b8", label: "Phone", r: 6 },
    url:            { color: "#ff9f43", label: "URL", r: 7 }
  };
  function typeOf(n) { return TYPE[n.type] || { color: "#8296b4", label: n.type || "node", r: 8 }; }

  function create(container, opts) {
    opts = opts || {};
    var low = (window.MTfx && window.MTfx.quality === "low");
    var reduce = !!(window.MTfx && window.MTfx.reduceMotion);
    var cvs = document.createElement("canvas");
    cvs.className = "graph-canvas";
    container.appendChild(cvs);
    var ctx = cvs.getContext("2d");
    var W = 0, H = 0, dpr = Math.min(window.devicePixelRatio || 1, low ? 1 : 2);

    var nodes = [], edges = [], byId = {};
    var hover = null, selected = null, dragging = null, pan = { x: 0, y: 0, s: 1 };
    var pointer = { x: -999, y: -999, inside: false };
    var alpha = 1, raf = 0, running = false, sim = true, appearT = 0, appearDur = 0;
    function smooth(x) { return x < 0 ? 0 : x > 1 ? 1 : x * x * (3 - 2 * x); }

    function resize() {
      W = container.clientWidth || 640; H = container.clientHeight || 420;
      cvs.width = W * dpr; cvs.height = H * dpr;
      cvs.style.width = W + "px"; cvs.style.height = H + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      draw();
    }

    /* ------------------------------------------------------------------ layout (force) ---- */
    function seedLayout() {
      var n = nodes.length || 1;
      for (var i = 0; i < nodes.length; i++) {
        var a = (i / n) * Math.PI * 2, r = 90 + (i % 3) * 55;
        nodes[i].x = Math.cos(a) * r; nodes[i].y = Math.sin(a) * r;
        nodes[i].vx = 0; nodes[i].vy = 0;
        nodes[i].deg = 0;
      }
    }
    function step() {
      var i, j, n = nodes.length, k = Math.sqrt((W * H) / Math.max(1, n)) * 0.55;
      for (i = 0; i < n; i++) {
        var a = nodes[i];
        for (j = i + 1; j < n; j++) {
          var b = nodes[j];
          var dx = b.x - a.x, dy = b.y - a.y, d2 = dx * dx + dy * dy || 0.01;
          var rep = (k * k * 26) / d2;
          var d = Math.sqrt(d2);
          var fx = (dx / d) * rep, fy = (dy / d) * rep;
          a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy;
        }
      }
      for (i = 0; i < edges.length; i++) {
        var e = edges[i], s = e.source, t = e.target;
        var ddx = t.x - s.x, ddy = t.y - s.y, dd = Math.sqrt(ddx * ddx + ddy * ddy) || 0.01;
        var want = 62 + (s.deg + t.deg) * 3;
        var f = (dd - want) * 0.035;
        var ux = (ddx / dd) * f, uy = (ddy / dd) * f;
        s.vx += ux; s.vy += uy; t.vx -= ux; t.vy -= uy;
      }
      // centre gravity + damping
      for (i = 0; i < n; i++) {
        var p = nodes[i];
        p.vx -= p.x * 0.012; p.vy -= p.y * 0.012;
        p.vx *= 0.82; p.vy *= 0.82;
        p.x += p.vx * alpha; p.y += p.vy * alpha;
      }
      alpha *= 0.985;
      if (alpha < 0.03) sim = false;
    }

    /* ---------------------------------------------------------------------- rendering ---- */
    function nodeRadius(nd) {
      var t = typeOf(nd);
      var base = t.r * (nd.weight ? (1 + Math.min(1.1, nd.weight / 60)) : 1);
      return base * (nd === hover ? 1.35 : 1) * (nd === selected ? 1.2 : 1);
    }
    function screen(p) { return { x: W / 2 + (p.x + pan.x) * pan.s, y: H / 2 + (p.y + pan.y) * pan.s }; }
    function draw() {
      ctx.clearRect(0, 0, W, H);
      if (!nodes.length) {
        ctx.fillStyle = "rgba(130,150,180,.75)"; ctx.font = "13px system-ui, sans-serif"; ctx.textAlign = "center";
        ctx.fillText("No relationships to draw yet — analyse an email to build the forensic graph.", W / 2, H / 2);
        return;
      }
      var i, nd, sp, dim = hover || selected;
      var elapsed = reduce ? 9999 : performance.now() - appearT;
      // edges
      for (i = 0; i < edges.length; i++) {
        var e = edges[i], a = screen(e.source), b = screen(e.target);
        var estep = edges.length > 60 ? Math.max(1, 700 / edges.length) : 16;
        var ae = smooth((elapsed - i * estep) / 420); if (ae <= 0) continue;
        var active = !dim || e.source === dim || e.target === dim;
        var mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
        var nx = -(b.y - a.y), ny = (b.x - a.x), nl = Math.sqrt(nx * nx + ny * ny) || 1;
        var cx = mx + (nx / nl) * 16 * pan.s, cy = my + (ny / nl) * 16 * pan.s;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y); ctx.quadraticCurveTo(cx, cy, b.x, b.y);
        var g = ctx.createLinearGradient(a.x, a.y, b.x, b.y);
        var ca = typeOf(e.source).color, cb = typeOf(e.target).color;
        g.addColorStop(0, hexA(ca, (active ? 0.55 : 0.10) * ae));
        g.addColorStop(1, hexA(cb, (active ? 0.55 : 0.10) * ae));
        ctx.strokeStyle = g; ctx.lineWidth = (active ? 1.5 : 1) * Math.max(0.7, pan.s);
        ctx.stroke();
        if (active && (hover || selected)) {                       // direction of the relationship
          var t = (Date.now() % 1600) / 1600;
          var px = (1 - t) * (1 - t) * a.x + 2 * (1 - t) * t * cx + t * t * b.x;
          var py = (1 - t) * (1 - t) * a.y + 2 * (1 - t) * t * cy + t * t * b.y;
          ctx.beginPath(); ctx.arc(px, py, 2.1 * pan.s, 0, 6.2832);
          ctx.fillStyle = hexA(typeOf(e.target).color, 0.9); ctx.fill();
          if (e.rel) {
            ctx.font = (9.5 * Math.max(0.85, pan.s)).toFixed(1) + "px ui-monospace, monospace";
            ctx.fillStyle = "rgba(190,210,235,.7)"; ctx.textAlign = "center";
            ctx.fillText(e.rel, px, py - 6);
          }
        }
      }
      // nodes
      for (i = 0; i < nodes.length; i++) {
        nd = nodes[i]; sp = screen(nd);
        var nstep = nodes.length > 45 ? Math.max(1.5, 900 / nodes.length) : 20;
        var an = smooth((elapsed - 260 - i * nstep) / 380); if (an <= 0) continue;
        var r = nodeRadius(nd) * pan.s * (0.45 + 0.55 * an), t = typeOf(nd);
        var fade = (dim ? (nd === dim || neighbor(dim, nd) ? 1 : 0.22) : 1) * an;
        if (nd.risk != null && nd.risk >= 60) {                     // threat halo
          ctx.beginPath(); ctx.arc(sp.x, sp.y, r * 2.1, 0, 6.2832);
          ctx.fillStyle = hexA("#ff5f6d", 0.07 * fade); ctx.fill();
        }
        ctx.beginPath(); ctx.arc(sp.x, sp.y, r, 0, 6.2832);
        var rg = ctx.createRadialGradient(sp.x - r * 0.3, sp.y - r * 0.4, r * 0.15, sp.x, sp.y, r);
        rg.addColorStop(0, hexA(t.color, 0.95 * fade));
        rg.addColorStop(1, hexA(t.color, 0.55 * fade));
        ctx.fillStyle = rg; ctx.fill();
        ctx.lineWidth = (nd === selected ? 2 : 1) * Math.max(0.8, pan.s);
        ctx.strokeStyle = hexA(nd === selected || nd === hover ? "#ffffff" : t.color, (nd === selected ? 0.9 : 0.5) * fade);
        ctx.stroke();
        // label
        var showLabel = pan.s > 0.75 && (nodes.length < 60 || nd === hover || nd === selected || nd.deg > 1);
        if (showLabel) {
          ctx.font = (11 * Math.max(0.9, pan.s)).toFixed(1) + "px system-ui, sans-serif";
          ctx.textAlign = "center";
          var txt = clip(String(nd.label || nd.id), 22);
          ctx.fillStyle = "rgba(8,12,20,.72)";
          var tw = ctx.measureText(txt).width;
          ctx.fillRect(sp.x - tw / 2 - 4, sp.y + r + 3, tw + 8, 14);
          ctx.fillStyle = "rgba(215,228,247," + (0.95 * fade).toFixed(2) + ")";
          ctx.fillText(txt, sp.x, sp.y + r + 14);
        }
      }
    }
    function neighbor(a, b) {
      for (var i = 0; i < edges.length; i++) {
        var e = edges[i];
        if ((e.source === a && e.target === b) || (e.target === a && e.source === b)) return true;
      }
      return false;
    }
    function hexA(hex, a) {
      var h = hex.replace("#", "");
      if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
      var n = parseInt(h, 16);
      return "rgba(" + ((n >> 16) & 255) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + a + ")";
    }
    function clip(s, n) { return s.length > n ? s.slice(0, n - 1) + "…" : s; }

    function frame() {
      raf = requestAnimationFrame(frame);
      if (sim) { for (var i = 0; i < (low ? 1 : 2); i++) step(); }
      var appearing = appearDur > 0 && (performance.now() - appearT) < appearDur;
      if (sim || hover || selected || appearing) draw(); else { if (alpha > 0) draw(); }
      if (!sim && !hover && !selected && !dragging && !appearing) { stop(); }
    }
    function start() { if (!running) { running = true; raf = requestAnimationFrame(frame); } }
    function stop() { running = false; if (raf) cancelAnimationFrame(raf); raf = 0; }

    /* --------------------------------------------------------------- interaction ---- */
    function pick() {
      if (!pointer.inside) return null;
      var best = null, bd = 1e9;
      for (var i = 0; i < nodes.length; i++) {
        var sp = screen(nodes[i]), r = nodeRadius(nodes[i]) * pan.s + 6;
        var d = (sp.x - pointer.x) * (sp.x - pointer.x) + (sp.y - pointer.y) * (sp.y - pointer.y);
        if (d < r * r && d < bd) { bd = d; best = nodes[i]; }
      }
      return best;
    }
    function onMove(e) {
      var r = cvs.getBoundingClientRect();
      pointer.x = e.clientX - r.left; pointer.y = e.clientY - r.top; pointer.inside = true;
      if (dragging) {
        dragging.x = (pointer.x - W / 2) / pan.s - pan.x + dragging.ox;
        dragging.y = (pointer.y - H / 2) / pan.s - pan.y + dragging.oy;
        dragging.vx = dragging.vy = 0; alpha = Math.max(alpha, 0.35); sim = true; start();
        draw();
        return;
      }
      var h = pick();
      if (h !== hover) {
        hover = h;
        container.classList.toggle("has-hover", !!h);
        cvs.style.cursor = h ? "pointer" : "grab";
        if (opts.onHover) opts.onHover(h, e.clientX - r.left, e.clientY - r.top);
        start();
      }
    }
    function onLeave() { pointer.inside = false; if (hover) { hover = null; if (opts.onHover) opts.onHover(null); start(); } }
    function onDown(e) {
      var h = pick();
      if (h) {
        dragging = h;
        dragging.ox = h.x - ((pointer.x - W / 2) / pan.s - pan.x);   // keep the grab offset stable
        dragging.oy = h.y - ((pointer.y - H / 2) / pan.s - pan.y);
        selected = h;
        if (opts.onSelect) opts.onSelect(h);
        start();
      } else {
        selected = null; panning = { x: e.clientX, y: e.clientY, px: pan.x, py: pan.y };
      }
    }
    var panning = null;
    function onUp() { dragging = null; panning = null; }
    function onPanMove(e) {
      if (!panning) return;
      pan.x = panning.px + (e.clientX - panning.x) / pan.s;
      pan.y = panning.py + (e.clientY - panning.y) / pan.s;
      draw();
    }
    function onWheel(e) {
      e.preventDefault();
      var r = cvs.getBoundingClientRect();
      var mx = e.clientX - r.left - W / 2, my = e.clientY - r.top - H / 2;
      var f = e.deltaY < 0 ? 1.12 : 1 / 1.12;
      var ns = Math.max(0.45, Math.min(2.6, pan.s * f));
      // keep the world point under the cursor fixed while zooming
      pan.x = mx / ns - mx / pan.s + pan.x;
      pan.y = my / ns - my / pan.s + pan.y;
      pan.s = ns;
      draw();
    }
    cvs.addEventListener("pointermove", function (e) { onMove(e); if (panning) onPanMove(e); });
    cvs.addEventListener("pointerdown", onDown);
    cvs.addEventListener("pointerup", onUp);
    cvs.addEventListener("pointercancel", onUp);
    cvs.addEventListener("pointerleave", onLeave);
    cvs.addEventListener("wheel", onWheel, { passive: false });
    window.addEventListener("resize", resize);

    /* public API -------------------------------------------------------------------------- */
    var api = {
      setData: function (data) {
        data = data || {};
        appearT = performance.now();
        var raw = (data.nodes || []).slice(0, 400);
        appearDur = reduce ? 0 : Math.min(2200, 300 + raw.length * 16 + 520);
        byId = {}; nodes = [];
        for (var i = 0; i < raw.length; i++) {
          var n = Object.assign({}, raw[i]);
          n.id = n.id || ("n" + i);
          byId[n.id] = n; nodes.push(n);
        }
        edges = [];
        for (var j = 0; j < (data.edges || []).length; j++) {
          var e = data.edges[j];
          var s = byId[e.source] || byId[e.from], t = byId[e.target] || byId[e.to];
          if (!s || !t || s === t) continue;
          var ed = { source: s, target: t, rel: e.rel || e.relation || "" };
          edges.push(ed); s.deg = (s.deg || 0) + 1; t.deg = (t.deg || 0) + 1;
        }
        seedLayout();
        alpha = 1; sim = true;
        pan = { x: 0, y: 0, s: 1 };
        if (reduce) { for (var k = 0; k < 320; k++) step(); sim = false; }
        resize(); start();
      },
      focus: function (id) {
        var n = byId[id]; if (!n) return;
        selected = n; start();
      },
      fit: function () { pan = { x: 0, y: 0, s: 1 }; draw(); },
      zoom: function (f) { pan.s = Math.max(0.45, Math.min(2.6, pan.s * f)); draw(); },
      stats: function () { return { nodes: nodes.length, edges: edges.length }; },
      resize: resize,
      dispose: function () {
        stop();
        window.removeEventListener("resize", resize);
        if (cvs.parentNode) cvs.parentNode.removeChild(cvs);
      }
    };
    resize();
    return api;
  }

  window.MTGraph = { create: create, TYPE: TYPE };
})();
