/* MailTrace AI — analyst dashboard (vanilla JS SPA, no build step) */
const $ = (s, el = document) => el.querySelector(s);
const view = $("#view");
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const fmtTs = t => t ? new Date(t).toLocaleString("en-IN", {hour12: false}) : "—";
const pct = x => Math.round((x || 0) * 100);
const analyst = () => $("#analyst").value || "analyst";
const api = async (path, opts = {}) => {
  const r = await fetch(path, {...opts, headers: {"X-Analyst": analyst(), ...(opts.headers || {})}});
  if (!r.ok) throw new Error((await r.text()) || r.statusText);
  return r.headers.get("content-type")?.includes("json") ? r.json() : r;
};
const toast = (title, body, alert = false) => {
  const el = document.createElement("div"); el.className = "tst" + (alert ? " alert" : "");
  el.innerHTML = `<b>${esc(title)}</b><span class="mini">${esc(body)}</span>`; $("#toast").appendChild(el); setTimeout(() => el.remove(), 6000);
};
/* Honest engine check: the packaged EXE may ship an older engine build. When that happens the
   monitoring/notification endpoints do not exist — say so instead of failing silently. */
const ENGINE_VERSION = "1.3.0";
function engineBanner(ver) {
  if (!ver || ver === ENGINE_VERSION || document.getElementById("mt-engbar")) return;
  const b = document.createElement("div");
  b.id = "mt-engbar"; b.className = "mt-engbar";
  b.innerHTML = `<i>ⓘ</i><div><b>Engine ${esc(ver)} detected — monitoring features need ${ENGINE_VERSION}</b>
    <span class="mini">Automatic Gmail/IMAP scanning, the startup catch-up scan and the notification history are provided by the
    updated engine. Start it with <code>python -m uvicorn main:app --host 0.0.0.0 --port 8000</code> from
    <code>_internal/backend</code>, then open <code>http://localhost:8000</code> — see RUN.txt.</span></div>
    <button class="btn sm" id="mt-engbar-x">Dismiss</button>`;
  document.body.insertBefore(b, document.body.firstChild);
  b.querySelector("#mt-engbar-x").onclick = () => b.remove();
}

/* ------------------------------------------------------------ desktop bridge (pywebview) */
const isDesktop = () => !!(window.pywebview && window.pywebview.api && typeof window.pywebview.api.info === "function");
// pywebview injects window.pywebview shortly AFTER page load; await this before using the bridge
const desktopReady = (ms = 2500) => new Promise(res => { if (isDesktop()) return res(true); const t0 = Date.now(); const tick = () => isDesktop() ? res(true) : (Date.now() - t0 > ms ? res(false) : setTimeout(tick, 50)); window.addEventListener("pywebviewready", () => setTimeout(tick, 0), {once: true}); tick(); });
const analyzePendingFiles = async () => {
  if (!isDesktop() || !window._handleFiles) return;
  try { const pend = await window.pywebview.api.take_pending_files(); if (!pend || !pend.length) return;
    const files = await window.pywebview.api.read_files(pend); const fl = files.filter(f => !f.error).map(f => new File([b64ToBlob(f.data_b64)], f.name));
    files.filter(f => f.error).forEach(f => toast("Could not read " + f.name, f.error, true)); if (fl.length) window._handleFiles(fl); } catch (e) { console.warn("pending files", e); }
};
const b64ToBlob = (b64, type = "message/rfc822") => { const bin = atob(b64); const u8 = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i); return new Blob([u8], {type}); };
window.desktop = {
  // File → Analyze email files… (native picker) → same upload path as the web drop-zone
  pickAndAnalyze: async () => {
    if (!isDesktop()) return;
    const paths = await window.pywebview.api.pick_eml_files();
    if (!paths || !paths.length) return;
    const files = await window.pywebview.api.read_files(paths);
    const fl = files.filter(f => !f.error).map(f => new File([b64ToBlob(f.data_b64)], f.name));
    files.filter(f => f.error).forEach(f => toast("Could not read " + f.name, f.error, true));
    if (!fl.length) return;
    if (location.hash !== "#/analyze") { location.hash = "#/analyze"; await new Promise(r => setTimeout(r, 350)); }
    if (window._handleFiles) window._handleFiles(fl);
  },
  // Export via native Save dialog, then offer to open the result
  exportCase: async (cid, kind, suggested) => {
    if (!isDesktop()) return false;
    const path = await window.pywebview.api.save_dialog(suggested);
    if (!path) return true;
    try {
      const r = await api(`/api/admin/export/${cid}/${kind}?path=${encodeURIComponent(path)}`);
      toast("Saved", `${r.bytes.toLocaleString()} bytes → ${path}`);
      if (kind === "pdf") window.pywebview.api.open_path(path);
    } catch (e) { toast("Export failed", e.message, true); }
    return true;
  }
};
document.addEventListener("click", e => {
  if (!isDesktop()) return;
  const a = e.target.closest("a[data-export]");
  if (a) { e.preventDefault(); window.desktop.exportCase(a.dataset.cid, a.dataset.export, a.dataset.name); return; }
  const ext = e.target.closest("a[href^='http']");
  if (ext && !ext.getAttribute("href").startsWith(location.origin)) { e.preventDefault(); window.pywebview.api.open_external(ext.href); }
});

const sevColor = {critical: "var(--crit)", high: "var(--high)", medium: "var(--med)", low: "var(--low)", info: "var(--ok)"};
const scoreColor = s => s >= 80 ? "#ef4444" : s >= 60 ? "#f97316" : s >= 35 ? "#eab308" : s >= 15 ? "#3b82f6" : "#22c55e";
const VERDICT_RISK = {malicious: 92, likely_malicious: 70, suspicious: 45, low_risk: 20, clean: 4};
const verdictBadge = (v, label) => `<span class="badge b-${v}">${esc(label || v)}</span>`;
const flag = cc => cc && cc.length === 2 && cc !== "--" && cc !== "??" ? String.fromCodePoint(...[...cc.toUpperCase()].map(c => 127397 + c.charCodeAt())) : "";


/* ------------------------------------------------------------ mailbox scope (select a mail ID first, then see only its emails) */
const mbGet = () => localStorage.getItem("mt_mailbox") || "";
const mbSet = v => { if (v) localStorage.setItem("mt_mailbox", v); else localStorage.removeItem("mt_mailbox"); document.querySelectorAll("#nav-mb").forEach(e => { e.hidden = !v; e.textContent = v ? "1" : ""; }); };
const mbQ = (first = "?") => mbGet() ? `${first}mailbox=${encodeURIComponent(mbGet())}` : "";
const mbIcon = m => ({imap: "📥", import: "🗂", sample: "🧪", upload: "⬆", batch: "⬆"}[m.source] || "▣");
let _mbCache = null;
async function mailboxes(force = false) { if (!_mbCache || force) _mbCache = await api("/api/mailboxes"); return _mbCache; }
/* selector bar rendered at the top of Dashboard / Cases / Campaigns / Link Analysis */
async function mailboxBar(onChange, title = "Mailbox") {
  const list = await mailboxes(true); const cur = mbGet();
  if (cur && !list.some(m => m.mailbox === cur)) mbSet("");
  const opts = list.map(m => `<option value="${esc(m.mailbox)}" ${m.mailbox === mbGet() ? "selected" : ""}>${mbIcon(m)} ${esc(m.mailbox)} — ${m.total} emails · ${m.malicious} malicious</option>`).join("");
  const sel = list.find(m => m.mailbox === mbGet());
  return `<div class="mbbar"><label>${esc(title)}</label><select id="mb-sel"><option value="">All mailboxes (${list.reduce((a, m) => a + m.total, 0)} emails)</option>${opts}</select>
    ${sel ? `<span class="mini">${mbIcon(sel)} ${esc(sel.source)} · ${sel.total} emails · <b style="color:var(--crit)">${sel.malicious}</b> malicious · ${sel.suspicious} suspicious · ${sel.campaigns} campaign(s) · last ${fmtTs(sel.last_at)}</span><button class="btn sm" id="mb-clear">✕ show all</button>` : `<span class="mini">Pick a mail ID or import file to see only its analysed emails.</span>`}
    <a class="btn sm" href="#/mailboxes" style="margin-left:auto">▣ Mailboxes overview</a></div>`;
}
function bindMailboxBar(onChange) {
  const sel = $("#mb-sel"); if (!sel) return;
  sel.onchange = () => { mbSet(sel.value); onChange(); };
  const cl = $("#mb-clear"); if (cl) cl.onclick = () => { mbSet(""); onChange(); };
}

/* ------------------------------------------------------------ router */
const routes = {};
function navigate() {
  const hash = (location.hash || "#/dashboard").split("?")[0];
  const [_, name, ...rest] = hash.split("/");
  document.querySelectorAll("nav a").forEach(a => a.classList.toggle("active", a.dataset.nav === name));
  // cinematic route change: a light veil sweeps across, then the new view animates in
  const endWipe = (window.MTmotion && window.MTmotion.route) ? window.MTmotion.route() : () => {};
  disposeVisuals();                                   // free WebGL / canvas resources before the next view
  view.classList.remove("mt-view-in");
  void view.offsetWidth;                              // restart the entry animation
  view.classList.add("mt-view-in");
  const r = (routes[name] || routes.dashboard)(rest.join("/"));
  if (r && r.catch) r.catch(() => {});
  if (r && r.finally) r.finally(endWipe); else endWipe();
  window.scrollTo({ top: 0, behavior: "smooth" });
}
window.addEventListener("hashchange", navigate);

/* ------------------------------------------------------------ live feed */
function connectEvents() {
  const es = new EventSource("/api/events");
  const feed = $("#feed");
  const push = (e, alert) => {
    const d = JSON.parse(e.data);
    const el = document.createElement("div"); el.className = "feed-item" + (alert ? " alert" : "");
    el.innerHTML = `<b>${alert ? "⚠ " : ""}${esc(d.label)} · ${d.score}</b><span class="mini">${esc((d.subject || "").slice(0, 44))}</span><br><small>${esc(d.sender || "")}${d.origin ? " · " + esc(d.origin) : ""}</small>`;
    el.onclick = () => location.hash = "#/case/" + d.case_id;
    feed.prepend(el); while (feed.children.length > 12) feed.lastChild.remove();
    if (alert) toast(`HIGH-RISK EMAIL — ${d.label} (${d.score})`, `${d.subject}  ·  from ${d.sender}`, true);
  };
  es.addEventListener("alert", e => { const d = JSON.parse(e.data); if (d.job_id && window._jobQuiet) { pushQuiet(d, true); } else push(e, true); });
  es.addEventListener("case", e => { const d = JSON.parse(e.data); if (d.job_id && window._jobQuiet) { pushQuiet(d, false); } else push(e, false); });
  es.addEventListener("job", e => onJobEvent(JSON.parse(e.data).job));
  es.addEventListener("notify", e => { if (window.MTConsole) window.MTConsole.onEvent(JSON.parse(e.data), "notify"); });
  es.addEventListener("job-done", e => { const d = JSON.parse(e.data); if (window.MTConsole) window.MTConsole.onEvent(d, "job-done"); });
  es.addEventListener("job-done", e => { const j = JSON.parse(e.data).job; onJobEvent(j); toast(`Import ${j.status}: ${j.label}`, `${j.analysed} analysed · ${j.malicious} malicious · ${j.duplicates} duplicates · ${j.errors} errors`, j.malicious > 0); if (location.hash.startsWith("#/sources")) routes.sources(); else if (location.hash.startsWith("#/dashboard")) routes.dashboard(); });
  // during bulk jobs, don't flood the feed with a toast per email — feed items only, no toasts
  const pushQuiet = (d, alert) => {
    const el = document.createElement("div"); el.className = "feed-item" + (alert ? " alert" : "");
    el.innerHTML = `<b>${alert ? "⚠ " : ""}${esc(d.label)} · ${d.score}</b><span class="mini">${esc((d.subject || "").slice(0, 44))}</span><br><small>${esc(d.sender || "")}${d.origin ? " · " + esc(d.origin) : ""}</small>`;
    el.onclick = () => location.hash = "#/case/" + d.case_id;
    feed.prepend(el); while (feed.children.length > 12) feed.lastChild.remove();
  };
  es.onerror = () => { $("#live-dot").classList.remove("live"); setTimeout(connectEvents, 4000); es.close(); };
  es.onopen = () => $("#live-dot").classList.add("live");
}

/* ------------------------------------------------------------ shared widgets */
function scoreRing(score, label) {
  const r = 50, c = 2 * Math.PI * r, col = scoreColor(score);
  return `<div class="score-ring"><svg width="120" height="120"><circle cx="60" cy="60" r="${r}" stroke="#1c2a44" stroke-width="10" fill="none"/><circle cx="60" cy="60" r="${r}" stroke="${col}" stroke-width="10" fill="none" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${c * (1 - score / 100)}"/></svg><div class="n"><b style="color:${col}">${Math.round(score)}</b><small>${esc(label)}</small></div></div>`;
}
function worldMap(path, opts = {}) {
  const W = 1000, H = 500;
  const proj = (lon, lat) => [(lon + 180) / 360 * W, (90 - lat) / 180 * H];
  const pts = (path || []).filter(p => p.lat != null && p.lon != null);
  let lines = "", dots = "";
  for (let i = 0; i < pts.length - 1; i++) {
    const [x1, y1] = proj(pts[i].lon, pts[i].lat), [x2, y2] = proj(pts[i + 1].lon, pts[i + 1].lat);
    const mx = (x1 + x2) / 2, my = Math.min(y1, y2) - Math.abs(x2 - x1) * 0.25 - 10;
    lines += `<path d="M${x1},${y1} Q${mx},${my} ${x2},${y2}" fill="none" stroke="#22d3ee" stroke-width="1.6" stroke-dasharray="6 4" opacity=".9"><animate attributeName="stroke-dashoffset" from="20" to="0" dur="1s" repeatCount="indefinite"/></path>`;
  }
  pts.forEach((p, i) => {
    const [x, y] = proj(p.lon, p.lat);
    const col = p.trust === "origin" ? "#ef4444" : p.trust === "trusted" ? "#22c55e" : "#94a3b8";
    const lbl = `${p.city || ""}${p.city ? ", " : ""}${p.countryCode || ""}`;
    dots += `<g><circle cx="${x}" cy="${y}" r="${p.trust === "origin" ? 9 : 6}" fill="${col}" opacity=".25">${p.trust === "origin" ? '<animate attributeName="r" values="9;18;9" dur="1.8s" repeatCount="indefinite"/><animate attributeName="opacity" values=".4;0;.4" dur="1.8s" repeatCount="indefinite"/>' : ""}</circle><circle cx="${x}" cy="${y}" r="4" fill="${col}" stroke="#fff" stroke-width="1"/><text x="${x + 8}" y="${y - 6}" font-size="11" fill="#e2e8f0" font-weight="600">${esc(lbl)}</text><text x="${x + 8}" y="${y + 6}" font-size="9" fill="#94a3b8">${esc(p.ip)}${p.trust === "origin" ? " · ORIGIN" : ""}</text></g>`;
  });
  if (opts.dest) { const [x, y] = proj(opts.dest.lon, opts.dest.lat); dots += `<g><rect x="${x - 5}" y="${y - 5}" width="10" height="10" fill="#22d3ee" transform="rotate(45 ${x} ${y})"/><text x="${x + 9}" y="${y + 4}" font-size="10" fill="#22d3ee">${esc(opts.dest.label || "recipient")}</text></g>`; if (pts.length) { const l = pts[pts.length - 1]; const [x1, y1] = proj(l.lon, l.lat); lines += `<path d="M${x1},${y1} Q${(x1 + x) / 2},${Math.min(y1, y) - Math.abs(x - x1) * 0.25 - 10} ${x},${y}" fill="none" stroke="#22d3ee" stroke-width="1.2" stroke-dasharray="3 4" opacity=".6"/>`; } }
  // coastlines: bundled GSHHS/Natural Earth geometry rendered flat when the 3D globe is unavailable
  const land = (() => {
    if ((window.WORLD_PATHS || []).length) return window.WORLD_PATHS.map(d => `<path class="land" d="${d}"/>`).join("");
    const w = window.MT_WORLD;
    if (!w) return "";
    const c = w.land.c, o = w.land.o, parts = [];
    for (let k = 0; k < o.length; k += 2) {
      const a = o[k], b = o[k + 1];
      let d = "";
      for (let i = a; i < b; i += 2) {
        const [x, y] = proj(c[i], c[i + 1]);
        d += (i === a ? "M" : "L") + x.toFixed(1) + "," + y.toFixed(1) + " ";
      }
      parts.push(`<path class="land" d="${d}Z"/>`);
    }
    return parts.join("");
  })();
  return `<svg class="map" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">${land}${lines}${dots}${pts.length === 0 ? `<text x="500" y="250" text-anchor="middle" fill="#64748b" font-size="14">No public relay IPs with geolocation</text>` : ""}</svg>`;
}
function hopList(path) {
  if (!path.length) return `<div class="empty">No Received headers to trace</div>`;
  return `<div class="hops">${path.map(p => `<div class="hop ${p.trust || ""}"><div class="pin">${p.position}</div><div class="body">
    <b>${esc(p.ip)}</b> ${p.private ? '<span class="tag">internal</span>' : `${flag(p.countryCode)} ${esc(window.MTgeo ? window.MTgeo.place(window.MTgeo.precision(p)) : ([p.city, p.region, p.country].filter(Boolean).join(", ") || "unknown"))}`}
    <div style="margin:3px 0">${window.MTgeo ? window.MTgeo.badge(p) : ""} ${window.MTgeo ? window.MTgeo.coordsRow(p) : ""}</div>
    ${p.trust === "origin" ? '<span class="tag bad">EARLIEST RELIABLE ORIGIN</span>' : p.trust === "trusted" ? '<span class="tag good">trusted receiver</span>' : '<span class="tag">unverifiable (below origin)</span>'}
    <div class="meta">${esc(p.rdns || p.host || "")}${p.by ? " → by " + esc(p.by) : ""}${p.isp ? " · " + esc(p.isp) : ""}${p.asn ? " · " + esc(p.asn) : ""}</div>
    <div class="meta">${p.timestamp ? fmtTs(p.timestamp) : "no timestamp"}${p.delay_s != null ? ` · +${p.delay_s}s` : ""}${p.protocol ? " · " + esc(p.protocol) : ""}${p.tls ? " · TLS" : " · <span style='color:#fdba74'>no TLS</span>"}${p.auth_submission ? " · <span style='color:#fca5a5'>authenticated submission</span>" : ""}</div>
    <div class="chip-row">${(p.tags || []).map(t => `<span class="tag ${/TOR|BULLET/.test(t) ? "bad" : /PROXY|VPN|HOSTING/.test(t) ? "warn" : ""}">${esc(t)}</span>`).join("")}</div>
  </div></div>`).join("")}</div>`;
}
function findingsList(fs) {
  if (!fs.length) return `<div class="empty">No findings</div>`;
  return fs.map(f => `<div class="finding"><div><span class="badge b-${f.severity}">${f.severity}</span></div><div><div class="t">${esc(f.title)}</div>${f.detail ? `<div class="d">${esc(f.detail)}</div>` : ""}<div class="w mono">${esc(f.code)}${f.weight ? " · weight " + f.weight : ""}</div></div></div>`).join("");
}
function categoryBars(cat) {
  const names = {identity_auth: "Identity & authentication", content: "Content / social engineering", links_attachments: "Links & attachments", infrastructure: "Infrastructure & domain intel"};
  return Object.entries(names).map(([k, n]) => `<div style="margin-bottom:8px"><div style="display:flex;justify-content:space-between;font-size:12px"><span>${n}</span><b>${cat[k] ?? 0}</b></div><div class="bar"><i style="width:${cat[k] ?? 0}%"></i></div></div>`).join("");
}

/* ------------------------------------------------------------ immersive visualisation layer */
/* Every widget below is bound to real backend data. WebGL widgets are created lazily and are
   disposed on navigation so repeated route changes cannot leak GPU resources. */
let _visuals = [];
function vtrack(o) { if (o) _visuals.push(o); return o; }
function disposeVisuals() {
  _visuals.forEach(v => { try { v && v.dispose && v.dispose(); } catch (e) { /* ignore */ } });
  _visuals = [];
}

const GLOBE_LEGEND = `<div class="globe-legend">
  <span><i style="background:#ff5f6d"></i>malicious origin</span>
  <span><i style="background:#ff9f43"></i>likely phishing</span>
  <span><i style="background:#ffd166"></i>suspicious</span>
  <span><i style="background:#59a8ff"></i>low risk</span>
  <span><i style="background:#3ddc97"></i>clean</span>
  <span><i style="background:#a78bfa;opacity:.6"></i>country-level (approximate)</span>
</div>`;

function globeShell(id, height) {
  return `<div class="globe-wrap" id="${id}" style="height:${height || "clamp(300px, 46vh, 460px)"}">
    <div class="globe-hud"><div class="l"><h3 style="margin:0">Global threat origins</h3>
      <div class="mini" id="${id}-sub">real geolocated origins of analysed mail</div></div>
      <div class="r globe-stats" id="${id}-stats"></div></div>
    <div class="globe-ctl">
      <button title="Zoom in" data-gz="in">+</button>
      <button title="Zoom out" data-gz="out">−</button>
      <button title="Reset view" data-gz="reset">⟲</button>
      <button title="Toggle rotation" data-gz="spin">↻</button>
    </div>${GLOBE_LEGEND}</div>`;
}

/* Create (or fall back from) the 3D globe. Returns the instance or null. */
function mountGlobe(container, data, opts = {}) {
  if (!container) return null;
  const tip = document.createElement("div");
  tip.className = "globe-tip";
  container.appendChild(tip);
  if (!window.MTfx || !window.MTfx.webgl || !window.MTGlobe || !window.THREE) {
    container.insertAdjacentHTML("beforeend", '<div class="geo-fallback">3D globe unavailable (no WebGL context) — showing the flat relay map instead.</div>');
    if (opts.fallbackHtml) container.insertAdjacentHTML("beforeend", opts.fallbackHtml);
    return null;
  }
  const ptr = { x: 20, y: 20 };
  container.addEventListener("pointermove", e => {
    const r = container.getBoundingClientRect();
    ptr.x = e.clientX - r.left; ptr.y = e.clientY - r.top;
  });
  let g = null;
  try {
    g = window.MTGlobe.create(container, {
    onHover: (p) => {
      if (!p) { tip.classList.remove("on"); return; }
      tip.innerHTML = `<b>${esc(p.city ? p.city + ", " : "")}${esc(p.country || "Unknown location")}</b>
        <div class="r"><span>IP</span><span>${esc(p.ip || "—")}</span></div>
        ${p.isp ? `<div class="r"><span>ISP</span><span>${esc(p.isp)}</span></div>` : ""}
        ${p.asn ? `<div class="r"><span>ASN</span><span>${esc(p.asn)}</span></div>` : ""}
        <div class="r"><span>Risk (max)</span><span style="color:${scoreColor(p.score || 0)}">${Math.round(p.score || 0)} / 100</span></div>
        ${p.count ? `<div class="r"><span>Emails</span><span>${p.count}</span></div>` : ""}
        ${p.category ? `<div class="r"><span>Infrastructure</span><span>${esc(p.category)}</span></div>` : ""}
        ${p.precision_label ? `<span class="apr">${esc(p.precision_label)}${p.approximate ? " · approximate position" : ""}</span>` : ""}
        ${p.caveat ? `<div class="r" style="opacity:.75"><span>${esc(p.caveat)}</span></div>` : ""}`;
      tip.classList.add("on");
      const pad = 14, tw = tip.offsetWidth, th = tip.offsetHeight;
      tip.style.left = Math.max(pad, Math.min(container.clientWidth - tw - pad, ptr.x + 16)) + "px";
      tip.style.top = Math.max(pad, Math.min(container.clientHeight - th - pad, ptr.y - 10)) + "px";
    },
    onSelect: (p) => { if (opts.onSelect) opts.onSelect(p); }
    });
  } catch (e) {                                        // never let a GPU problem break the route
    g = null;
    container.insertAdjacentHTML("beforeend", '<div class="geo-fallback">3D globe could not start (' + esc(e.message || e) + ") — showing the flat relay map instead.</div>");
    if (opts.fallbackHtml) container.insertAdjacentHTML("beforeend", opts.fallbackHtml);
    return null;
  }
  if (!g || g.unsupported) return null;
  // a lost WebGL context (driver reset / GPU switch) must not leave a dead canvas behind
  container.querySelector("canvas")?.addEventListener("webglcontextlost", ev => {
    ev.preventDefault(); g.stop();
    container.insertAdjacentHTML("beforeend", '<div class="geo-fallback">WebGL context lost — reload the page to restore the 3D globe. The flat relay map is shown below.</div>');
    if (opts.fallbackHtml) container.insertAdjacentHTML("beforeend", opts.fallbackHtml);
  });
  g.setData(data);
  container.querySelectorAll("[data-gz]").forEach(b => b.onclick = () => {
    const z = b.dataset.gz;
    if (z === "in") { g.zoomBy(1 / 1.2); g.setAutoRotate(false); }
    else if (z === "out") { g.zoomBy(1.2); g.setAutoRotate(false); }
    else if (z === "reset") { g.focus(20, 78, 3.15); g.setAutoRotate(true); }
    else if (z === "spin") { g.setAutoRotate(!g.isSpinning()); }
  });
  if (opts.focus && isFinite(opts.focus.lat)) g.focus(opts.focus.lat, opts.focus.lon, opts.focus.zoom || 2.6);
  const stop = window.MTfx.whenVisible(container, () => g.start(), () => g.stop());
  return vtrack({ dispose: () => { stop(); g.dispose(); }, api: g });
}

/* Build globe input from a real analysis result: origin + every relay hop that has coordinates. */
function globeDataFromResult(r) {
  const geo = r.geo || {}, path = r.trace_path || [];
  const seen = {}, points = [];
  (path || []).forEach(p => {
    if (!p || p.private || p.lat == null || p.lon == null) return;
    if (seen[p.ip]) return; seen[p.ip] = 1;
    const g = geo[p.ip] || {};
    const prec = window.MTgeo ? window.MTgeo.precision(p) : { level: "country", approximate: true, label: "Country-level" };
    points.push({
      lat: p.lat, lon: p.lon, ip: p.ip, country: p.country, city: p.city, region: p.region,
      isp: p.isp || g.isp, asn: p.asn, category: p.category, tags: p.tags,
      score: p.trust === "origin" ? r.score.score : Math.max(8, r.score.score * 0.45),
      count: 1, precision: prec.level, precision_label: prec.label, approximate: prec.approximate,
      caveat: prec.caveat, trust: p.trust, case_id: r.id
    });
  });
  // origin that resolved only to a country: plot the country centroid, clearly marked approximate
  const a = r.attribution || {}, og = a.origin_geo || {};
  if (a.origin_ip && og.country && (og.lat == null || og.lon == null)) {
    const cc = (og.countryCode || "").toUpperCase();
    const c = window.MT_CENTROIDS && window.MT_CENTROIDS[cc];
    if (c) points.push({
      lat: c[0], lon: c[1], ip: a.origin_ip, country: og.country, city: "", region: "",
      isp: og.isp, asn: og.as, category: og.category, tags: og.tags, score: r.score.score, count: 1,
      precision: "country", precision_label: "Country-level — centroid, coordinates not returned",
      approximate: true, caveat: "Only the country is known; marker sits at the country centroid for orientation, not an observed position",
      trust: "origin", case_id: r.id
    });
  }
  const arcs = [];
  for (let i = 0; i < path.length - 1; i++) {
    const a1 = path[i], b1 = path[i + 1];
    if (a1.lat == null || b1.lat == null) continue;
    arcs.push({ from: { lat: a1.lat, lon: a1.lon }, to: { lat: b1.lat, lon: b1.lon }, score: r.score.score, case_id: r.id, hop: a1.position });
  }
  return { points, arcs };
}

/* ------------------------------------------------------------ forensic timeline (real timestamps only) */
function forensicTimeline(c) {
  const r = c.result || {}, h = r.headers || {}, ev = [];
  const add = (ts, title, detail, src, sev) => {
    const t = ts ? new Date(ts) : null;
    ev.push({ t: (t && !isNaN(t)) ? t : null, raw: ts || "", title, detail: detail || "", src: src || "", sev: sev || "" });
  };
  // registration events from RDAP (real dates returned by the registry)
  const di = r.domain_intel || {};
  if (di.found && di.created) add(di.created, "Sender domain registered", `${di.domain} via ${di.registrar || "unknown registrar"}${di.age_days != null ? " · " + di.age_days + " days before analysis" : ""}`, "RDAP", "warn");
  Object.entries(r.url_domain_intel || {}).forEach(([d, x]) => {
    if (x && x.found && x.created) add(x.created, "Link domain registered", `${d}${x.age_days != null ? " · " + x.age_days + " days old at analysis" : ""}`, "RDAP", "warn");
  });
  if (h.date) add(h.date, "Message composed", `Date header as written by the sender's client${h.x_mailer ? " · X-Mailer " + h.x_mailer : ""}`, "header Date");
  // relay chain: each Received timestamp is real evidence of when a server handled the message
  (r.trace_path || []).forEach(p => {
    if (!p.timestamp) return;
    add(p.timestamp, `Hop ${p.position} handled by ${p.by || p.rdns || p.host || p.ip}`,
      `${p.ip}${p.city || p.country ? " · " + [p.city, p.country].filter(Boolean).join(", ") : ""}${p.delay_s != null ? " · +" + p.delay_s + "s after previous hop" : ""}${p.tls ? " · TLS" : ""}`,
      "Received header", p.trust === "origin" ? "bad" : "");
  });
  if (r.analyzed_at) add(r.analyzed_at, "Analysis completed",
    `risk ${r.score.score}/100 · ${r.score.label} · ${(r.threat.primary || "").replace(/_/g, " ")} · ${r.timing_ms} ms${r.analysis_depth === "triage" ? " (triage pass)" : ""}`,
    "MailTrace AI", r.score.score >= 60 ? "bad" : r.score.score >= 35 ? "warn" : "");
  (c.custody || []).forEach(x => add(x.ts, `Chain of custody: ${x.action}`, `${x.actor}${x.detail ? " · " + x.detail : ""}`, "custody log"));
  const withT = ev.filter(e => e.t).sort((a, b) => a.t - b.t);
  const noT = ev.filter(e => !e.t);
  const item = (e, i) => `<div class="tl-item ${e.sev}" style="--i:${i}"><div class="tl-t">${e.t ? esc(e.t.toISOString().replace("T", " ").slice(0, 19)) + " UTC" : "time not recorded"}</div>
    <div class="tl-h">${esc(e.title)}</div>${e.detail ? `<div class="tl-d">${esc(e.detail)}</div>` : ""}
    <div class="tl-src">source: ${esc(e.src || "—")}</div></div>`;
  const list = withT.length ? withT.map(item).join("") : "";
  const rest = noT.length ? noT.map(item).join("") : "";
  if (!list && !rest) return `<div class="empty">No timestamped forensic events are available for this message.</div>`;
  return `<div class="tl">${list}${rest}</div>`;
}

/* ------------------------------------------------------------ interactive forensic graph */
function mountGraph(container, data, opts = {}) {
  if (!container) return null;
  if (!window.MTGraph) return null;
  const tip = document.createElement("div");
  tip.className = "graph-tip";
  container.appendChild(tip);
  const card = document.createElement("div");
  card.className = "node-card";
  card.hidden = true;
  container.appendChild(card);
  const g = window.MTGraph.create(container, {
    onHover: (n, x, y) => {
      if (!n) { tip.classList.remove("on"); return; }
      const t = window.MTGraph.TYPE[n.type] || { label: n.type, color: "#8296b4" };
      tip.innerHTML = `<b>${esc(n.label || n.id)}</b><div class="r">${esc(t.label)}${n.score != null ? " · risk " + Math.round(n.score) : ""}${n.country ? " · " + esc(n.country) : ""}${n.isp ? " · " + esc(n.isp) : ""}${n.risk != null ? " · url risk " + n.risk : ""}</div>`;
      tip.classList.add("on");
      tip.style.left = Math.min(container.clientWidth - 250, x + 14) + "px";
      tip.style.top = Math.max(8, y - 12) + "px";
    },
    onSelect: n => {
      if (!n) { card.hidden = true; return; }
      const t = window.MTGraph.TYPE[n.type] || { label: n.type, color: "#8296b4" };
      card.hidden = false;
      card.innerHTML = `<span class="x" title="close">✕</span><h4><i style="width:9px;height:9px;border-radius:50%;background:${t.color};display:inline-block"></i> ${esc(t.label)}</h4>
        <dl class="kv">
          <dt>Value</dt><dd class="mono" style="word-break:break-all">${esc(n.label || n.id)}</dd>
          ${n.score != null ? `<dt>Risk</dt><dd><b style="color:${scoreColor(n.score)}">${Math.round(n.score)}</b> / 100</dd>` : ""}
          ${n.risk != null ? `<dt>URL risk</dt><dd>${esc(n.risk)}</dd>` : ""}
          ${n.country ? `<dt>Country</dt><dd>${esc(n.country)}</dd>` : ""}
          ${n.isp ? `<dt>ISP</dt><dd>${esc(n.isp)}</dd>` : ""}
          ${n.trust ? `<dt>Relay trust</dt><dd>${esc(n.trust)}</dd>` : ""}
          ${n.campaign ? `<dt>Campaign</dt><dd>${esc(n.campaign)}</dd>` : ""}
          ${n.sha256 ? `<dt>SHA-256</dt><dd class="mono">${esc(n.sha256)}</dd>` : ""}
          <dt>Connections</dt><dd>${n.deg || 0}</dd>
        </dl>
        ${n.case_id ? `<a class="btn sm" href="#/case/${encodeURIComponent(n.case_id)}" style="margin-top:8px">Open case →</a>` : ""}`;
      card.querySelector(".x").onclick = () => { card.hidden = true; };
      if (opts.onSelect) opts.onSelect(n);
    }
  });
  const legend = Object.keys(window.MTGraph.TYPE).filter(k => ["email", "sender", "domain", "url_domain", "ip", "asn", "attachment", "wallet", "phone", "upi", "location"].includes(k))
    .map(k => `<span><i style="background:${window.MTGraph.TYPE[k].color}"></i>${window.MTGraph.TYPE[k].label}</span>`).join("");
  container.insertAdjacentHTML("beforeend", `<div class="graph-legend">${legend}</div>
    <div class="graph-ctl"><button data-g="in">+</button><button data-g="out">−</button><button data-g="fit">⤢</button></div>`);
  container.querySelectorAll("[data-g]").forEach(b => b.onclick = () => {
    if (b.dataset.g === "in") g.zoom(1.18); else if (b.dataset.g === "out") g.zoom(1 / 1.18); else g.fit();
  });
  g.setData(data || { nodes: [], edges: [] });
  return vtrack({ dispose: () => g.dispose(), api: g });
}

/* ------------------------------------------------------------ force graph (tiny) */
function forceGraph(container, data, onClick) {
  const W = container.clientWidth || 900, H = container.clientHeight || 560;
  const colors = {email: "#22d3ee", sender: "#f59e0b", reply_to: "#fb923c", return_path: "#a78bfa", domain: "#f472b6", url_domain: "#ef4444", ip: "#eab308", asn: "#64748b", attachment: "#e879f9", wallet: "#84cc16", phone: "#2dd4bf", upi: "#84cc16", origin_ip: "#eab308", sender_domain: "#f472b6", file_sha256: "#e879f9"};
  const nodes = data.nodes.map((n, i) => ({...n, x: W / 2 + Math.cos(i) * 120 + (Math.random() - .5) * 60, y: H / 2 + Math.sin(i) * 120 + (Math.random() - .5) * 60, vx: 0, vy: 0}));
  const idx = Object.fromEntries(nodes.map(n => [n.id, n]));
  const edges = data.edges.filter(e => idx[e.source] && idx[e.target]).map(e => ({...e, s: idx[e.source], t: idx[e.target]}));
  const deg = {}; edges.forEach(e => { deg[e.source] = (deg[e.source] || 0) + 1; deg[e.target] = (deg[e.target] || 0) + 1; });
  const rad = n => n.type === "email" ? 9 : 5 + Math.min(8, (deg[n.id] || 1) * 1.4);
  // simulation: Fruchterman-Reingold style with cooling; leaf nodes are pulled tight to their hub
  const N = nodes.length, area = W * H, k = Math.sqrt(area / Math.max(1, N)) * 0.42;
  let temp = Math.min(W, H) / 6;
  nodes.forEach((n, i) => { const ang = i / N * Math.PI * 2, rr = Math.min(W, H) * 0.32; n.x = W / 2 + Math.cos(ang) * rr; n.y = H / 2 + Math.sin(ang) * rr; });
  for (let it = 0; it < 320; it++) {
    nodes.forEach(n => { n.dx = 0; n.dy = 0; });
    for (let i = 0; i < N; i++) for (let j = i + 1; j < N; j++) {
      const a = nodes[i], b = nodes[j]; let dx = a.x - b.x, dy = a.y - b.y; let d = Math.hypot(dx, dy) || 0.01;
      if (d > 260) continue;
      const f = k * k / d; dx = dx / d * f; dy = dy / d * f; a.dx += dx; a.dy += dy; b.dx -= dx; b.dy -= dy;
    }
    edges.forEach(e => { const dx = e.t.x - e.s.x, dy = e.t.y - e.s.y, d = Math.hypot(dx, dy) || 0.01; const leaf = (deg[e.s.id] === 1 || deg[e.t.id] === 1) ? 1.8 : 1; const f = d * d / k * 0.9 * leaf; e.s.dx += dx / d * f; e.s.dy += dy / d * f; e.t.dx -= dx / d * f; e.t.dy -= dy / d * f; });
    nodes.forEach(n => { n.dx += (W / 2 - n.x) * 0.05; n.dy += (H / 2 - n.y) * 0.09; const d = Math.hypot(n.dx, n.dy) || 0.01, step = Math.min(d, temp); n.x += n.dx / d * step; n.y += n.dy / d * step;
      // soft walls: push back proportionally instead of clamping (prevents pile-ups on the border)
      const mx = 40, my = 30; if (n.x < mx) n.x += (mx - n.x) * 0.5; if (n.x > W - 130) n.x -= (n.x - (W - 130)) * 0.5; if (n.y < my) n.y += (my - n.y) * 0.5; if (n.y > H - my) n.y -= (n.y - (H - my)) * 0.5; });
    temp = Math.max(0.6, temp * 0.985);
  }
  const svg = `<svg viewBox="0 0 ${W} ${H}">
    ${edges.map(e => `<line class="gedge" x1="${e.s.x}" y1="${e.s.y}" x2="${e.t.x}" y2="${e.t.y}"/>`).join("")}
    ${nodes.map(n => `<g class="gnode" data-id="${esc(n.id)}" style="cursor:${n.type === "email" ? "pointer" : "default"}"><circle cx="${n.x}" cy="${n.y}" r="${rad(n)}" fill="${colors[n.type] || "#94a3b8"}" stroke="${n.type === "email" ? scoreColor(n.score || 0) : "#0b1220"}" stroke-width="${n.type === "email" ? 3 : 1.2}" opacity=".95"><title>${esc(n.type)}: ${esc(n.label)}${n.score != null ? " · score " + n.score : ""}${n.campaign ? " · " + n.campaign : ""}${n.country ? " · " + n.country : ""}${n.isp ? " · " + n.isp : ""}</title></circle><text x="${n.x + rad(n) + 3}" y="${n.y + 3}">${esc(n.label.length > 26 ? n.label.slice(0, 25) + "…" : n.label)}</text></g>`).join("")}
  </svg>
  <div class="legend">${Object.entries(colors).filter(([k]) => ["email", "sender", "reply_to", "domain", "url_domain", "ip", "asn", "attachment", "wallet", "phone"].includes(k)).map(([k, c]) => `<span style="--c:${c}">${k.replace("_", " ")}</span>`).join("")}</div>`;
  container.innerHTML = svg;
  container.querySelectorAll(".gnode").forEach(g => g.onclick = () => onClick && onClick(idx[g.dataset.id]));
}

/* ------------------------------------------------------------ views */
routes.dashboard = async () => {
  // skeleton first (shimmer placeholders, not a spinner) so the entrance reads as a real console booting
  const sk = window.MTmotion ? window.MTmotion.skeleton : n => '<div class="skel"></div>'.repeat(n || 3);
  view.innerHTML = `<div class="page-head"><div><div class="eyebrow">Threat intelligence overview</div><h1>Command Center</h1>
      <div class="sub" style="margin:0">loading live telemetry…</div></div></div>
    <div class="hero"><div class="card">${sk(4)}<div class="skel tall"></div></div><div class="card">${sk(6)}</div></div>
    <div class="card pad0" style="margin:16px 0"><div class="skel tall" style="height:clamp(320px,48vh,470px);margin:0"></div></div>
    <div class="grid g32"><div class="card">${sk(5)}</div><div class="card">${sk(4)}</div></div>`;
  const [st, cases, camps, health, bar, hot, mon] = await Promise.all([
    api("/api/stats" + mbQ()), api("/api/cases?limit=12" + mbQ("&")), api("/api/campaigns" + mbQ()),
    api("/api/health"), mailboxBar(() => routes.dashboard()),
    api("/api/geo/hotspots" + mbQ()).catch(() => ({ points: [], arcs: [], totals: {}, countries: [] })),
    api("/api/monitor").catch(e => (window.__engineLegacy = /404|405|Not Found|Method Not Allowed/i.test(e.message || ""), null))
  ]);
  const mal = (st.by_verdict.malicious || 0) + (st.by_verdict.likely_malicious || 0);
  const m = health.model || {};
  const avg = st.total ? Object.entries(st.by_verdict).reduce((a, [k, v]) => a + v * (VERDICT_RISK[k] || 0), 0) / st.total : 0;
  const t = hot.totals || {};
  view.innerHTML = `
    <div class="page-head" data-reveal>
      <div>
        <div class="eyebrow">Threat intelligence overview</div>
        <h1>Command Center</h1>
        <div class="sub" style="margin:0">${esc(health.org)} · ${st.total} emails analysed${mbGet() ? ` in <b>${esc(mbGet())}</b>` : ` across ${st.mailboxes || 0} mailbox(es)`} · ${health.offline ? "OFFLINE mode (bundled seeds)" : "live enrichment — DNS · GeoIP · RDAP · Tor exit list"}</div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn" id="load-samples">▶ Run demo corpus</button>
        <a class="btn" href="#/sources">⇊ Connect mailbox / bulk import</a>
        <a class="btn p" href="#/analyze">⚡ Analyze email</a>
      </div>
    </div>
    ${bar}

    <div class="card mon-bar" data-reveal>
      ${mon ? `
      <div class="mon-dot ${mon.enabled && mon.selected ? "on" : ""}"></div>
      <div><b>${mon.enabled ? (mon.selected ? "Monitoring " + mon.selected + " of " + mon.accounts + " account(s)" : "Monitoring idle — no account selected") : "Monitoring paused"}</b>
        <span class="mini">${mon.last_catchup ? `startup catch-up ${esc(mon.last_catchup)} · ` : ""}${mon.last_tick ? `last scheduler check ${esc(mon.last_tick)} · ` : ""}${(mon.active_jobs || []).length} scan(s) running · ${(mon.idle_watchers || []).length} push connection(s)</span></div>
      <div class="sp"></div>
      <a class="btn sm" href="#/accounts">◉ Mail Accounts</a>
      ${mon.selected ? `<button class="btn sm" id="dash-scan">⇊ Scan now</button>` : ""}
      ` : `
      <div class="mon-dot"></div>
      <div><b>Mailbox monitoring needs the updated engine</b>
        <span class="mini">This build is running an older engine, so automatic Gmail/IMAP scanning, the
        startup catch-up scan and notification history are not available. Start the updated engine with
        <code>python -m uvicorn main:app --host 0.0.0.0 --port 8000</code> from
        <code>_internal/backend</code> and open <code>http://localhost:8000</code> (see RUN.txt).</span></div>
      <div class="sp"></div><a class="btn sm" href="#/accounts">◉ Mail Accounts</a>`}
    </div>

    <div class="hero" data-reveal>
      <div class="card accent" style="display:flex;flex-direction:column;justify-content:center;gap:12px">
        <div class="row-between"><h3 style="margin:0">Threat posture</h3><span class="mini">${st.total} analysed</span></div>
        <div class="hero-stats mt-seq">
          <div><div class="v" style="color:var(--crit)" data-count="${mal}">0</div><div class="l">Malicious / likely</div><div class="d">score ≥ 60</div></div>
          <div><div class="v" style="color:var(--amber)" data-count="${st.open_high}">0</div><div class="l">Open high-risk</div><div class="d">awaiting action</div></div>
          <div><div class="v" style="color:var(--cy)" data-count="${st.campaigns}">0</div><div class="l">Campaigns</div><div class="d">shared infrastructure</div></div>
          <div><div class="v" style="color:var(--green)" data-count="${(st.by_verdict.clean || 0) + (st.by_verdict.low_risk || 0)}">0</div><div class="l">Clean / low risk</div><div class="d">authenticated</div></div>
        </div>
        <div class="risk-meter">
          <div class="row-between"><h3 style="margin:0">Mean risk score</h3><b style="font-size:19px;color:${scoreColor(avg)}" data-count="${avg}" data-dec="1">0</b></div>
          <div class="risk-bar"><i style="left:0" data-risk="${avg}"></i></div>
          <div class="risk-scale"><span>clean</span><span>low</span><span>suspicious</span><span>likely</span><span>malicious</span></div>
        </div>
      </div>
      <div class="card" style="display:flex;flex-direction:column;gap:10px">
        <div class="hd" style="margin:0"><h2 style="margin:0">Priority investigations</h2><a href="#/cases">all cases →</a></div>
        <div class="threat-list mt-seq">
          ${cases.filter(c => (c.score || 0) >= 15).slice(0, 8).map(c => `<div class="threat-row" data-case="${esc(c.id)}">
            <div class="sev" style="background:${scoreColor(c.score)}"></div>
            <div class="t"><b>${esc(c.subject || "(no subject)")}</b><span>${esc(c.sender || "")}${c.origin_country ? " · " + esc(c.origin_city ? c.origin_city + ", " + c.origin_country : c.origin_country) : ""}</span></div>
            <div class="s" style="color:${scoreColor(c.score)}">${Math.round(c.score || 0)}</div>
          </div>`).join("") || '<div class="mini">Nothing above low risk. Analyse an email or run the demo corpus.</div>'}
        </div>
      </div>
    </div>

    <div class="card pad0" style="margin-bottom:16px" data-reveal data-par="16">
      ${globeShell("globe-main", "clamp(320px, 48vh, 470px)")}
      <div style="padding:10px 14px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;border-top:1px solid var(--stroke)">
        <span class="mini">${t.located || 0} of ${t.cases || 0} cases plotted from real GeoIP coordinates${t.no_coordinates ? ` · <b>${t.no_coordinates}</b> country-level only (no coordinates returned — not plotted as precise pins)` : ""}${t.unknown ? ` · ${t.unknown} unresolved` : ""}</span>
        <span class="mini">${t.anonymised ? `${t.anonymised} via anonymising infrastructure · ` : ""}${t.tor ? `${t.tor} via Tor exit nodes` : ""}${!t.tor && !t.anonymised ? "drag to rotate · scroll to zoom · hover a node for detail" : ""}</span>
      </div>
    </div>

    <div class="grid g32" style="margin-bottom:16px" data-reveal>
      <div class="card"><div class="hd"><h2>Recent analyses</h2><a href="#/cases">all cases →</a></div>
        ${cases.length ? `<table><thead><tr><th>Risk</th><th>Subject / sender</th><th>Threat</th><th>Origin</th><th>Campaign</th></tr></thead><tbody>${cases.map(c => `<tr class="row" data-case="${esc(c.id)}"><td><b style="color:${scoreColor(c.score)}">${Math.round(c.score)}</b></td><td><span class="ell">${esc(c.subject)}</span><span class="ell mini">${esc(c.sender)}</span></td><td>${verdictBadge(c.verdict, (c.threat || "").replace(/_/g, " "))}</td><td>${c.origin_country ? `${esc(c.origin_city || "")} ${esc(c.origin_country)}` : "—"}<br><span class="mini mono">${esc(c.origin_ip || "")}</span></td><td>${c.campaign_id ? `<a href="#/campaigns">${c.campaign_id}</a>` : "—"}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">No cases yet. Click <b>Run demo corpus</b> to analyse the 11 bundled sample emails, or upload your own .eml.</div>`}
      </div>
      <div class="grid" style="gap:16px">
        <div class="card"><h3>Threat mix</h3>${Object.entries(st.by_threat).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<div style="display:flex;justify-content:space-between;font-size:12.5px;margin-bottom:4px"><span>${esc(k.replace(/_/g, " "))}</span><b>${v}</b></div><div class="bar" style="margin-bottom:8px"><i style="width:${st.total ? v / st.total * 100 : 0}%"></i></div>`).join("") || '<div class="mini">—</div>'}</div>
        <div class="card"><h3>Origin countries (risk ≥ 35)</h3>${(hot.countries || st.by_country || []).map(c => `<div style="display:flex;justify-content:space-between;font-size:12.5px;margin-bottom:5px"><span>${esc(c.country)}</span><b>${c.count}</b></div>`).join("") || '<div class="mini">—</div>'}</div>
        <div class="card"><h3>Attribution scenarios</h3>${Object.entries(st.by_scenario).map(([k, v]) => `<div style="display:flex;justify-content:space-between;font-size:12.5px;margin-bottom:5px"><span>${esc(k.replace(/_/g, " "))}</span><b>${v}</b></div>`).join("") || '<div class="mini">—</div>'}</div>
      </div>
    </div>

    <div class="grid g2" data-reveal>
      <div class="card"><div class="hd"><h2>Active campaigns</h2><a href="#/campaigns">details →</a></div>${camps.length ? camps.map(c => `<div style="padding:8px 0;border-bottom:1px solid var(--stroke)"><b>${esc(c.name)}</b> <span class="badge b-mut">${c.member_count} emails</span><div class="chip-row" style="margin-top:4px">${c.shared_indicators.slice(0, 6).map(i => `<span class="tag">${esc(i)}</span>`).join("")}</div></div>`).join("") : '<div class="mini">No campaigns yet — campaigns appear automatically when ≥2 malicious emails share infrastructure (sender, reply-to, origin IP, URL domain, file hash, wallet, UPI, phone).</div>'}</div>
      <div class="card"><h2>Detection engine</h2><dl class="kv"><dt>NLP model</dt><dd>${esc(m.model || "—")}</dd><dt>Training data</dt><dd>${esc(m.dataset || "—")} (${m.train_rows || "—"} rows)</dd><dt>Hold-out accuracy</dt><dd><b>${m.accuracy ? (m.accuracy * 100).toFixed(2) + "%" : "—"}</b> · ROC-AUC ${m.roc_auc || "—"} · phishing F1 ${m.phishing_f1 || "—"} (n=${m.holdout_rows || "—"})</dd><dt>Header forensics</dt><dd>Received-chain reconstruction, earliest-reliable-origin heuristic, SPF live evaluation (RFC 7208 subset), DKIM crypto verification, DMARC policy + alignment, timestamp/timezone consistency</dd><dt>Geolocation</dt><dd>ip-api GeoIP + ASN + Tor exit list, RDAP netblock &amp; abuse contact. Precision is reported per record (city / region / country / unavailable) and coordinates are never invented</dd><dt>Correlation</dt><dd>Shared-indicator graph → connected-component campaign clustering (NetworkX)</dd></dl></div>
    </div>`;

  bindMailboxBar(() => routes.dashboard());
  const dashScan = $("#dash-scan");
  if (dashScan) dashScan.onclick = async e => {
    e.target.disabled = true; e.target.textContent = "Scanning…";
    try { const r = await api("/api/monitor/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode: "incremental" }) });
      const bad = (r.jobs || []).filter(j => j.error);
      toast(bad.length ? "Scan could not start" : "Scan started", bad.length ? bad[0].error : "fetching new mail since the last checkpoint", !!bad.length);
      setTimeout(() => routes.dashboard(), 1500);
    } catch (err) { toast("Scan failed", err.message, true); e.target.disabled = false; e.target.textContent = "⇊ Scan now"; }
  };
  view.querySelectorAll("[data-case]").forEach(el => el.onclick = () => location.hash = "#/case/" + el.dataset.case);
  // animated counters + risk needle (real values only)
  view.querySelectorAll("[data-count]").forEach(el => window.MTfx.count(el, parseFloat(el.dataset.count) || 0, { decimals: parseInt(el.dataset.dec || 0) }));
  const needle = view.querySelector("[data-risk]");
  if (needle) requestAnimationFrame(() => { needle.style.left = Math.max(0, Math.min(99.4, parseFloat(needle.dataset.risk) || 0)) + "%"; });
  const gEl = $("#globe-main");
  if (gEl) {
    let globe = null;
    const stats = $("#globe-main-stats"), sub = $("#globe-main-sub");
    if (stats) stats.innerHTML = `<b>${hot.points ? hot.points.length : 0}</b>geolocated origins`;
    globe = mountGlobe(gEl, hot, {
      onSelect: p => { if (p && p.cases && p.cases.length) location.hash = "#/case/" + p.cases[0].id; },
      focus: (hot.points && hot.points[0]) ? { lat: hot.points[0].lat, lon: hot.points[0].lon, zoom: 2.7 } : null
    });
    if (sub && hot.points && hot.points.length) sub.textContent = "hover or click a node to inspect the originating infrastructure";
    // micro-interaction: hovering an investigation flies the globe to that message's real origin
    view.querySelectorAll(".threat-row").forEach(row => row.addEventListener("mouseenter", () => {
      const p = (hot.points || []).find(x => (x.cases || []).some(cs => cs.id === row.dataset.case));
      if (p && globe && globe.api) globe.api.focus(p.lat, p.lon, 2.5);
    }));
  }
  if (window.MTfx) view.querySelectorAll(".hero > .card").forEach(c => vtrack(window.MTfx.tilt(c, 4)));
  const btn = $("#load-samples");
  btn.onclick = async e => {
    e.target.disabled = true; e.target.textContent = "Analysing 11 samples… (live DNS/GeoIP, ~1 min)";
    try { const r = await api("/api/samples/load_all", { method: "POST" }); toast("Demo corpus analysed", `${r.length} emails · ${r.filter(x => x.score >= 60).length} high-risk`); routes.dashboard(); }
    catch (err) { toast("Error", err.message, true); e.target.disabled = false; }
  };
  window.MTfx.reveal(view);
};

routes.analyze = async () => {
  const samples = await api("/api/samples");
  view.innerHTML = `
    <div class="page-head" data-reveal>
      <div><div class="eyebrow">Investigation intake</div><h1>Analyze Email</h1>
      <div class="sub" style="margin:0">Upload a raw <b>.eml</b> (File → Save as / "Show original" → Download) or paste full source including headers. The pipeline below advances on <b>real backend events</b> — header forensics, live SPF/DKIM/DMARC, NLP classification, URL/attachment inspection, GeoIP + RDAP enrichment and campaign correlation.</div></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap"><a class="btn" href="#/sources">⇊ Bulk import</a><a class="btn p" href="#/dashboard">◀ Command center</a></div>
    </div>
    <div class="grid g23" data-reveal>
      <div>
        <div class="drop" id="drop"><div style="font-size:30px">📨</div><b>Drop .eml files here</b><div class="mini">or click to browse · multiple files supported</div><input type="file" id="file" accept=".eml,.msg,.txt,message/rfc822" multiple hidden></div>
        <div style="margin:16px 0 6px;font-weight:600">…or paste raw message source</div>
        <textarea id="raw" placeholder="Return-Path: <...>\nReceived: from ...\nFrom: ...\nSubject: ...\n\nbody..."></textarea>
        <div style="display:flex;gap:8px;margin-top:8px;align-items:center;flex-wrap:wrap"><button class="btn p" id="go">⚡ Analyze pasted source</button><label class="mini" style="display:flex;gap:6px;align-items:center"><input type="checkbox" id="persist" checked> save as case (evidence preserved + custody log)</label></div>
      </div>
      <div class="card"><div class="hd"><h2 style="margin:0">Demo corpus (${samples.length})</h2><span class="mini">realistic scenarios for an Indian institution</span></div>
        <div class="samples mt-seq">${samples.map(s => `<div class="sample" data-n="${esc(s.name)}"><b>${esc(s.subject)}</b><small>${esc(s.from)}</small><small class="mono">${esc(s.name)} · ${s.size} B</small></div>`).join("")}</div></div>
    </div>
    <div id="progress" style="margin-top:18px"></div>`;

  /* Streams NDJSON stage events from /api/analyze/stream. Each node lights up only when the
     backend reports that the work behind it has finished; the metrics are the backend's own. */
  const runStream = async (fd, label) => {
    const holder = $("#progress");
    holder.innerHTML = `<div class="card"><div class="hd"><h2 style="margin:0">Investigation pipeline</h2><span class="mini" id="pipe-target">${esc(label)}</span></div><div class="pipe" id="pipe"></div></div>`;
    const pipe = window.MTPipeline.create($("#pipe"), {});
    // immersive AI-processing texture — runs only while the backend is actually working
    const scanCard = holder.querySelector(".card");
    const scan = (window.MTmotion && scanCard) ? window.MTmotion.aiScan(scanCard) : null;
    if (scan) vtrack(scan);
    try {
      const res = await fetch(fd.url || "/api/analyze/stream", { method: "POST", body: fd.body, headers: { "X-Analyst": analyst() } });
      // Older builds (frozen EXE) have no streaming endpoint: fall back to the classic request and
      // report honestly — the stages then complete together when the analysis returns.
      if ((res.status === 404 || res.status === 405 || !res.body) && fd.fallbackUrl) {
        pipe.note("live stage streaming unavailable on this backend — stages complete together when the analysis returns");
        window.MTPipeline.STAGES.forEach(st => pipe.stage(st.id, "run", {}));
        const r = await api(fd.fallbackUrl, { method: "POST", body: fd.body });
        window.MTPipeline.STAGES.forEach(st => pipe.stage(st.id, "done", {}));
        pipe.done(); if (scan) scan.done();
        if (r.case_id) location.hash = "#/case/" + r.case_id; else { window._adhoc = r; location.hash = "#/adhoc"; }
        return;
      }
      if (!res.ok || !res.body) throw new Error((await res.text()) || res.statusText);
      const reader = res.body.getReader();
      const dec = typeof TextDecoder !== "undefined" ? new TextDecoder("utf-8") : null;
      const utf8 = u8 => { let s = ""; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return decodeURIComponent(escape(s)); };
      let buf = "", bytes = new Uint8Array(0), result = null, err = null;
      const onLine = line => {
        line = line.trim(); if (!line) return;
        let ev; try { ev = JSON.parse(line); } catch (e) { return; }
        if (ev.type === "stage") pipe.stage(ev.id, ev.status, ev);
        else if (ev.type === "result") result = ev.result;
        else if (ev.type === "error") err = ev.message;
      };
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (dec) {
          buf += dec.decode(value, { stream: true });
          let i;
          while ((i = buf.indexOf("\n")) >= 0) { onLine(buf.slice(0, i)); buf = buf.slice(i + 1); }
        } else {                                   // very old runtimes without TextDecoder: split on the raw 0x0A byte
          const nb = new Uint8Array(bytes.length + value.length); nb.set(bytes); nb.set(value, bytes.length); bytes = nb;
          let i;
          while ((i = bytes.indexOf(10)) >= 0) { onLine(utf8(bytes.slice(0, i))); bytes = bytes.slice(i + 1); }
        }
      }
      if (dec) onLine(buf); else if (bytes.length) onLine(utf8(bytes));
      if (err) throw new Error(err);
      if (!result) throw new Error("stream ended without a result");
      pipe.done(); if (scan) scan.done();
      if (result.case_id) location.hash = "#/case/" + result.case_id;
      else { window._adhoc = result; location.hash = "#/adhoc"; }
    } catch (e) {
      pipe.fail(e.message); if (scan) scan.fail();
      toast("Analysis failed", e.message, true);
    }
  };

  const drop = $("#drop"), file = $("#file");
  drop.onclick = async () => (await desktopReady(300)) ? window.desktop.pickAndAnalyze() : file.click();
  ["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
  const handleFiles = async files => {
    if (files.length === 1) {
      const b = new FormData(); b.append("file", files[0]); b.append("persist", $("#persist").checked);
      runStream({ url: "/api/analyze/stream", fallbackUrl: "/api/analyze", body: b }, files[0].name);
    } else {
      const b = new FormData(); [...files].forEach(f => b.append("files", f));
      $("#progress").innerHTML = `<div class="loading"><div class="spin"></div> Batch analysing ${files.length} files…</div>`;
      const r = await api("/api/analyze/batch", { method: "POST", body: b });
      $("#progress").innerHTML = `<div class="card"><h2>Batch results</h2><table><thead><tr><th>File</th><th>Score</th><th>Verdict</th><th>Threat</th></tr></thead><tbody>${r.map(x => `<tr class="row" data-case="${x.case_id}"><td>${esc(x.file)}</td><td><b style="color:${scoreColor(x.score || 0)}">${x.score ?? "—"}</b></td><td>${x.error ? esc(x.error) : esc(x.label)}</td><td>${esc(x.threat || "")}</td></tr>`).join("")}</tbody></table></div>`;
      $("#progress").querySelectorAll("[data-case]").forEach(t => t.onclick = () => location.hash = "#/case/" + t.dataset.case);
    }
  };
  window._handleFiles = handleFiles;
  desktopReady().then(ok => ok && analyzePendingFiles());
  drop.addEventListener("drop", e => handleFiles(e.dataTransfer.files));
  file.onchange = () => handleFiles(file.files);
  $("#go").onclick = () => {
    const raw = $("#raw").value.trim(); if (!raw) return toast("Paste a message first", "");
    const b = new FormData(); b.append("raw_text", raw); b.append("persist", $("#persist").checked);
    runStream({ url: "/api/analyze/stream", fallbackUrl: "/api/analyze", body: b }, "pasted source");
  };
  document.querySelectorAll(".sample").forEach(s => s.onclick = () => {
    const b = new FormData(); b.append("persist", $("#persist").checked);
    const u = "/api/samples/" + encodeURIComponent(s.dataset.n) + "/analyze";
    runStream({ url: u + "/stream", fallbackUrl: u, body: b }, s.dataset.n);
  });
  window.MTfx.reveal(view);
};

routes.adhoc = () => { if (!window._adhoc) return location.hash = "#/analyze"; renderCase({id: window._adhoc.id, result: window._adhoc, custody: [], related: [], indicators: [], status: "adhoc", analyst_notes: "", tags: []}, true); };

routes.case = async cid => {
  view.innerHTML = `<div class="loading"><div class="spin"></div> Loading case…</div>`;
  try { renderCase(await api("/api/cases/" + cid)); } catch (e) { view.innerHTML = `<div class="empty">Case not found</div>`; }
};

/* Threat result identity: MALICIOUS / SUSPICIOUS / CLEAN with the real evidence behind it.
   Nothing is invented — missing confidence or NLP output is shown as unavailable. */
function verdictHero(r, c) {
  const s = r.score, v = s.verdict;
  const band = (v === "malicious" || v === "likely_malicious") ? "malicious" : (v === "suspicious" ? "suspicious" : "clean");
  const title = band === "malicious" ? "MALICIOUS" : band === "suspicious" ? "SUSPICIOUS" : "CLEAN / LOW RISK";
  const expl = band === "malicious"
    ? "Treat this message as hostile. Do not click links, open attachments or reply — evidence and indicators are preserved below for blocking and LEA hand-off."
    : band === "suspicious"
      ? "Indicators are mixed. Verify the sender through a second channel before acting on any request in this message."
      : "No credible threat indicators were found: authentication, links, attachments and sender infrastructure check out.";
  const nlp = (r.content && r.content.nlp) ? r.content.nlp.phishing_probability : null;
  const f = r.findings || [];
  const n = sev => f.filter(x => String(x.severity || "").toLowerCase() === sev).length;
  const ioc = r.iocs || {};
  const iocN = ["sender", "reply_to", "return_path", "origin_ip", "domains", "urls", "attachment_hashes", "crypto_wallets", "upi_ids", "phones"]
    .reduce((a, k) => a + (ioc[k] ? (Array.isArray(ioc[k]) ? ioc[k].length : 1) : 0), 0);
  return `<div class="verdict-hero ${band}">
    <div class="vh-mark"><i></i></div>
    <div class="vh-main">
      <div class="vh-top"><b>${title}</b><span class="vh-score" style="color:${scoreColor(s.score)}">${Math.round(s.score)}<small>/100</small></span>
        <span class="tag">${esc(s.label)}</span>${r.threat && r.threat.primary ? `<span class="tag">${esc(r.threat.primary.replace(/_/g, " "))}</span>` : ""}
        ${r.analysis_depth === "triage" ? '<span class="tag warn" title="no live DNS/GeoIP yet — enrichment pending">provisional · triage</span>' : ""}</div>
      <div class="vh-expl">${esc(expl)}</div>
    </div>
    <div class="vh-stats">
      <div><label>NLP confidence</label><b>${nlp != null ? (nlp * 100).toFixed(1) + "% phishing" : "unavailable"}</b></div>
      <div><label>Findings</label><b>${f.length} · ${n("critical") + n("high")} high+</b></div>
      <div><label>Indicators</label><b>${iocN}</b></div>
      <div><label>Analysed</label><b class="mono">${fmtTs(r.analyzed_at)}</b></div>
    </div>
  </div>`;
}

function renderCase(c, adhoc = false) {
  const r = c.result, h = r.headers, a = r.attribution, s = r.score, au = h.auth, g = a.origin_geo || {};
  const authBadge = v => `<span class="badge ${v === "pass" ? "b-ok" : v === "fail" ? "b-critical" : v === "softfail" ? "b-high" : v === "none" || !v ? "b-mut" : "b-medium"}">${esc(v || "none")}</span>`;
  const di = r.domain_intel || {}, reg = r.origin_ip_registry || {};
  const tabs = ["Overview", "Trace & Geo", "Headers & Auth", "Content & NLP", "Indicators", "Graph", "Timeline", "Report & Custody"];
  view.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;margin-bottom:12px">
      <div style="min-width:0"><div class="mini">CASE ${esc(c.id)} · analysed ${fmtTs(r.analyzed_at)} · ${r.timing_ms} ms${r.analysis_depth === "triage" ? ' · <span class="badge b-medium" title="provisional score: no live DNS/GeoIP yet — enrichment pending">triage</span>' : ""} ${c.campaign_id ? `· <a href="#/campaigns">${c.campaign_id}</a>` : ""}${c.source && c.source !== "upload" ? ` · via <span class="mono" title="${esc(c.source_ref || "")}">${esc(c.source)}${c.source_ref ? ": " + esc(c.source_ref.split(" | ")[0].slice(0, 70)) : ""}</span>` : ""} ${adhoc ? '· <span class="badge b-medium">not saved</span>' : `· status <span class="badge b-mut">${esc(c.status)}</span>`}</div>
        <h1 style="font-size:19px;word-break:break-word">${esc(h.subject || "(no subject)")}</h1>
        <div class="mini">From <b>${esc(h.from.name || "")}</b> &lt;${esc(h.from.address)}&gt; → ${esc(h.to)}${h.reply_to.address ? ` · Reply-To <span style="color:#fdba74">${esc(h.reply_to.address)}</span>` : ""}</div></div>
      <div style="display:flex;gap:6px;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end">${adhoc ? "" : `<a class="btn" href="/api/cases/${c.id}/report.pdf" target="_blank" data-export="pdf" data-cid="${c.id}" data-name="MailTrace_${c.id}.pdf">📄 Forensic PDF</a><a class="btn sm" href="/api/cases/${c.id}/iocs.csv" data-export="csv" data-cid="${c.id}" data-name="iocs_${c.id}.csv">IOC CSV</a><a class="btn sm" href="/api/cases/${c.id}/report.json" target="_blank" data-export="json" data-cid="${c.id}" data-name="MailTrace_${c.id}.json">JSON</a><a class="btn sm" href="/api/cases/${c.id}/evidence.eml" data-export="eml" data-cid="${c.id}" data-name="evidence_${c.id}.eml">Evidence .eml</a>`}</div>
    </div>
    ${verdictHero(r, c)}
    <div class="grid mt-seq" style="grid-template-columns:150px 1fr 1fr 1fr;margin-bottom:14px">
      <div class="card" style="display:flex;align-items:center;justify-content:center">${scoreRing(s.score, s.label)}</div>
      <div class="card"><h3>Classification</h3><div style="margin-bottom:6px">${verdictBadge(s.verdict, s.label)} <span class="badge b-mut">${esc(r.threat.primary.replace(/_/g, " "))}</span> ${r.threat.secondary.map(t => `<span class="badge b-mut">${esc(t.replace(/_/g, " "))}</span>`).join(" ")}</div>${r.threat.bec.length ? `<div class="mini">BEC patterns: ${r.threat.bec.map(esc).join(" · ")}</div>` : ""}<div style="margin-top:8px">${categoryBars(s.category_pct)}</div>${s.trust_credits?.length ? `<div class="mini" style="color:#86efac">Trust credits: ${s.trust_credits.map(esc).join("; ")}</div>` : ""}</div>
      <div class="card"><h3>Authentication</h3><dl class="kv"><dt>SPF</dt><dd>${authBadge(au.spf)} <span class="mini">${au.spf_aligned ? "aligned" : "not aligned"} · ${esc(au.spf_domain || "")}</span></dd><dt>DKIM</dt><dd>${authBadge(au.dkim)} <span class="mini">${au.dkim_domains.length ? "d=" + au.dkim_domains.map(esc).join(", ") : "no signature"}${au.dkim_aligned ? " · aligned" : ""}${au.dkim_crypto_verified === true ? " · crypto ✓" : au.dkim_crypto_verified === false ? " · crypto ✗" : ""}</span></dd><dt>DMARC</dt><dd>${authBadge(au.dmarc)} <span class="mini">p=${esc(au.dmarc_policy || "none")}</span></dd><dt>Return-Path</dt><dd class="mini">${esc(h.return_path.address || "—")}</dd><dt>Message-ID</dt><dd class="mini mono">${esc(h.message_id || "(missing)")}</dd></dl></div>
      <div class="card"><h3>Probable origin</h3><div style="font-size:19px;font-weight:700;line-height:1.25">${flag(g.countryCode)} ${esc(window.MTgeo ? window.MTgeo.place(window.MTgeo.precision(g)) : ([g.city, g.country].filter(Boolean).join(", ") || "Unknown"))}</div>
        <div style="margin:6px 0 4px">${window.MTgeo ? window.MTgeo.badge(g) : ""}</div>
        <div class="mini" style="margin-bottom:2px">${window.MTgeo ? window.MTgeo.coordsRow(g) : (g.lat != null ? `<span class="mono">${g.lat}, ${g.lon}</span>` : '<span class="geo-na">Coordinates unavailable</span>')}</div>
        ${(g.geo_precision && g.geo_precision.caveat) ? `<div class="mini" style="color:var(--amber);margin:4px 0">${esc(g.geo_precision.caveat)}</div>` : ""}
        <div class="mini">${esc(a.origin_ip || "no origin IP")} · ${esc(g.isp || "")}</div><div class="mini">${esc(g.as || "")}</div><div style="margin:6px 0"><span class="tag ${/anonymised|bulletproof/.test(g.category || "") ? "bad" : /cloud|provider/.test(g.category || "") ? "warn" : "good"}">${esc(g.category || "—")}</span></div><div class="conf">location confidence <div class="bar"><i style="width:${pct(a.location_confidence)}%"></i></div> ${pct(a.location_confidence)}%</div><div class="conf">attribution confidence <div class="bar"><i style="width:${pct(a.confidence)}%"></i></div> ${pct(a.confidence)}%</div><div style="margin-top:6px"><b>${esc(a.scenario_label)}</b></div></div>
    </div>
    <div class="tabs">${tabs.map((t, i) => `<button class="${i === 0 ? "active" : ""}" data-t="${i}">${t}</button>`).join("")}</div>
    <div id="tab"></div>`;
  const panes = [
    () => `<div class="summary" style="margin-bottom:14px">${esc(r.summary)}</div>
      <div class="grid g32"><div class="card"><h2>Evidence (${r.findings.length} findings)</h2>${findingsList(r.findings)}</div>
      <div><div class="card" style="margin-bottom:14px"><h2>Attribution reasoning</h2><ul style="margin:0;padding-left:18px;font-size:13px">${a.reasons.map(x => `<li style="margin-bottom:5px">${esc(x)}</li>`).join("")}</ul></div>
      <div class="card" style="margin-bottom:14px"><h2>Recommended actions</h2><ol class="reco" style="margin:0;padding-left:18px;font-size:13px">${recommendations(r).map(x => `<li>${esc(x)}</li>`).join("")}</ol></div>
      ${c.related?.length ? `<div class="card"><h2>Related cases (shared infrastructure)</h2>${c.related.map(x => `<div style="padding:6px 0;border-bottom:1px solid var(--line)"><a href="#/case/${x.case_id}"><b style="color:${scoreColor(x.score)}">${Math.round(x.score)}</b> ${esc(x.subject)}</a><div class="chip-row">${x.shared.map(i => `<span class="tag">${esc(i)}</span>`).join("")}</div></div>`).join("")}</div>` : ""}</div></div>`,
    () => `<div class="card pad0" style="margin-bottom:14px">
        ${globeShell("globe-case", "clamp(300px, 44vh, 430px)")}
        <div style="padding:9px 14px;border-top:1px solid var(--stroke);display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap">
          <span class="mini" id="globe-case-note">origin and relay hops plotted from real GeoIP coordinates</span>
          <span class="mini">${(r.trace_path || []).filter(p => p.lat != null).length} of ${(r.trace_path || []).length} hops geolocated</span>
        </div></div>
      <div class="grid g23"><div class="card"><h2>Relay chain (origin → recipient)</h2>${hopList(r.trace_path)}<div class="mini" style="margin-top:10px">Origin method: <b>${esc(h.origin.origin_kind.replace(/_/g, " "))}</b> (hop confidence ${pct(h.origin.confidence)}%). ${h.origin.notes.map(esc).join(" ")}</div></div>
      <div><div class="card" style="margin-bottom:14px"><h2>Origin IP intelligence</h2><dl class="kv"><dt>IP</dt><dd class="mono">${esc(a.origin_ip || "—")}</dd><dt>GeoIP</dt><dd>${esc([g.city, g.regionName, g.country].filter(Boolean).join(", ") || "—")}${g.lat ? ` <span class="mini">(${g.lat}, ${g.lon})</span>` : ""}</dd><dt>Timezone</dt><dd>${esc(g.timezone || "—")}</dd><dt>ISP / Org</dt><dd>${esc(g.isp || "—")}${g.org && g.org !== g.isp ? " · " + esc(g.org) : ""}</dd><dt>ASN</dt><dd>${esc(g.as || "—")}</dd><dt>Reverse DNS</dt><dd class="mono">${esc(g.reverse || "none")}</dd><dt>Classification</dt><dd>${(g.tags || []).map(t => `<span class="tag ${/TOR|BULLET/.test(t) ? "bad" : /PROXY|VPN|HOSTING/.test(t) ? "warn" : ""}">${esc(t)}</span>`).join("")}</dd><dt>RIR netblock</dt><dd>${reg.found ? `${esc(reg.netname || "")} · ${esc(reg.rir || "")} · ${esc(reg.start || "")} – ${esc(reg.end || "")} · country ${esc(reg.country || "?")}${reg.org ? " · " + esc(reg.org) : ""}` : "—"}</dd><dt>Abuse contact</dt><dd>${(reg.abuse_contacts || []).map(esc).join(", ") || "—"}</dd></dl></div>
      <div class="card"><h2>Sender domain intelligence</h2><dl class="kv"><dt>Domain</dt><dd>${esc(di.domain || h.from.registered_domain || "—")}</dd>${di.found ? `<dt>Registered</dt><dd>${esc((di.created || "").slice(0, 10))} <b style="color:${di.age_days < 180 ? "#fca5a5" : "#86efac"}">(${di.age_days} days old)</b></dd><dt>Registrar</dt><dd>${esc(di.registrar || "—")}</dd><dt>Registrant</dt><dd>${esc(di.registrant || (di.privacy_proxy ? "redacted / privacy" : "—"))}${di.registrant_country ? " · " + esc(di.registrant_country) : ""}</dd><dt>Nameservers</dt><dd class="mono">${(di.nameservers || []).map(esc).join(", ") || "—"}</dd><dt>Expires</dt><dd>${esc((di.expires || "").slice(0, 10))}</dd>` : `<dt>Registration</dt><dd>${di.freemail ? "free webmail provider" : esc(di.note || "no RDAP data")}</dd><dt>Resolves</dt><dd>${di.resolves === false ? '<span style="color:#fca5a5">no A/MX records</span>' : di.resolves ? "yes" : "—"}</dd>`}<dt>MX</dt><dd class="mono">${(au.live.mx || []).map(esc).join(", ") || "—"}</dd><dt>SPF record</dt><dd class="mono">${esc(au.live.spf_record || "—")}</dd><dt>DMARC record</dt><dd class="mono">${esc(au.live.dmarc_record || "—")}</dd></dl>
      ${Object.keys(r.url_domain_intel || {}).length ? `<h3 style="margin-top:12px">Link domains</h3>${Object.entries(r.url_domain_intel).map(([d, x]) => `<div class="mini"><b>${esc(d)}</b>: ${x.found ? `registered ${esc((x.created || "").slice(0, 10))} (${x.age_days} d) via ${esc(x.registrar || "?")}` : esc(x.note || "no data")}</div>`).join("")}` : ""}</div></div></div>`,
    () => `<div class="grid g2"><div class="card"><h2>Identity fields</h2><dl class="kv"><dt>From</dt><dd>${esc(h.from.raw)}</dd><dt>Reply-To</dt><dd>${esc(h.reply_to.raw || "—")}</dd><dt>Return-Path</dt><dd>${esc(h.return_path.address || "—")}</dd><dt>To</dt><dd>${esc(h.to)}</dd><dt>Date</dt><dd>${esc(h.date || "—")}</dd><dt>Message-ID</dt><dd class="mono">${esc(h.message_id || "(missing)")}</dd><dt>X-Mailer</dt><dd>${esc(h.x_mailer || "—")}</dd><dt>X-Originating-IP</dt><dd>${esc(h.x_originating_ip || "—")}</dd></dl>
      <h3 style="margin-top:14px">Live checks</h3><dl class="kv"><dt>SPF eval</dt><dd>${esc(au.live.spf_detail || "—")}</dd><dt>DKIM</dt><dd>${esc(au.live.dkim_detail || "—")}</dd><dt>Receiver Auth-Results</dt><dd class="mono">${au.receiver_auth_results.map(esc).join("<br>") || "— none in message"}</dd><dt>ARC</dt><dd>${esc(au.arc || "—")}</dd></dl></div>
      <div class="card"><h2>Header & auth findings</h2>${findingsList(r.findings.filter(f => /^(H|A|I)-/.test(f.code)))}</div></div>
      <div class="card" style="margin-top:14px"><h2>Raw Received chain (top = nearest recipient)</h2>${h.hops.map(x => `<pre style="max-height:none;margin-bottom:6px;border-left:3px solid ${x.trust === "origin" ? "var(--crit)" : x.trust === "trusted" ? "var(--ok)" : "#475569"}">#${x.position} [${esc(x.trust || "?")}] ${esc(x.raw)}</pre>`).join("") || '<div class="mini">none</div>'}</div>`,
    () => { const n = r.content.nlp, f = r.content.features, b = r.content.body; return `<div class="grid g2"><div class="card"><h2>NLP classifier</h2>${n.phishing_probability != null ? `<div style="display:flex;align-items:center;gap:14px"><div style="font-size:34px;font-weight:700;color:${scoreColor(n.phishing_probability * 100)}">${(n.phishing_probability * 100).toFixed(1)}%</div><div class="mini">phishing probability<br>${esc(n.model || "")}</div></div><div style="margin-top:8px"><div class="mini">Terms pushing toward <b style="color:#fca5a5">phishing</b>:</div>${n.top_terms.map(t => `<span class="term" title="${t.weight}">${esc(t.term)}</span>`).join("") || "—"}</div><div style="margin-top:6px"><div class="mini">Terms pushing toward <b style="color:#86efac">legitimate</b>:</div>${(n.legit_terms || []).map(t => `<span class="term g" title="${t.weight}">${esc(t.term)}</span>`).join("") || "—"}</div>` : `<div class="mini">${esc(n.note || "n/a")}</div>`}
        <h3 style="margin-top:14px">Social-engineering cues (score ${f.cue_score}/100)</h3>${Object.entries(f.cues).map(([k, v]) => `<div style="font-size:12.5px;margin-bottom:4px"><b>${esc(k.replace(/_/g, " "))}</b> ×${v.count}: <span class="mini">${v.matches.map(m => `"${esc(m)}"`).join(", ")}</span></div>`).join("") || '<div class="mini">none</div>'}
        <h3 style="margin-top:14px">BEC / fraud patterns</h3>${Object.entries(f.bec_patterns).map(([k, v]) => `<div style="font-size:12.5px;margin-bottom:4px"><span class="badge b-high">${esc(k)}</span> <span class="mini">${v.map(m => `"${esc(m)}"`).join(", ")}</span></div>`).join("") || '<div class="mini">none</div>'}
        <h3 style="margin-top:14px">Extracted entities</h3><dl class="kv"><dt>Money</dt><dd>${f.money_mentions.map(esc).join(", ") || "—"}</dd><dt>Phones</dt><dd>${f.phone_numbers.map(esc).join(", ") || "—"}</dd><dt>UPI IDs</dt><dd>${f.upi_ids.map(esc).join(", ") || "—"}</dd><dt>Crypto wallets</dt><dd class="mono">${f.crypto_wallets.map(esc).join(", ") || "—"}</dd><dt>Words / length</dt><dd>${f.word_count} / ${f.length}</dd></dl></div>
      <div><div class="card" style="margin-bottom:14px"><h2>Links (${r.content.urls.count})</h2>${r.content.urls.urls.map(u => `<div class="urlrow"><div class="risk" style="background:${scoreColor(u.risk)}22;color:${scoreColor(u.risk)}">${u.risk}</div><div style="min-width:0"><code>${esc(u.url.slice(0, 140))}</code>${u.anchor ? `<div class="mini">anchor text: "${esc(u.anchor.slice(0, 80))}"</div>` : ""}<div class="chip-row">${u.flags.map(x => `<span class="tag ${/Impersonat|Lookalike|@|IP/.test(x) ? "bad" : "warn"}">${esc(x)}</span>`).join("")}</div></div></div>`).join("") || '<div class="mini">no links</div>'}</div>
      <div class="card" style="margin-bottom:14px"><h2>Attachments (${r.content.attachments.count})</h2>${r.content.attachments.attachments.map(x => `<div class="urlrow"><div class="risk" style="background:${scoreColor(x.risk)}22;color:${scoreColor(x.risk)}">${x.risk}</div><div style="min-width:0"><b>${esc(x.filename)}</b> <span class="mini">${esc(x.content_type)} · ${x.size} B</span><div class="mini mono">sha256 ${esc(x.sha256)}</div><div class="chip-row">${x.flags.map(f => `<span class="tag bad">${esc(f)}</span>`).join("")}</div></div></div>`).join("") || '<div class="mini">no attachments</div>'}</div>
      <div class="card"><h2>HTML construction</h2><dl class="kv"><dt>Hidden elements</dt><dd>${b.hidden_elements}</dd><dt>Scripts / iframes</dt><dd>${b.scripts} / ${b.iframes}</dd><dt>Forms</dt><dd>${b.forms.map(esc).join(", ") || "none"}</dd><dt>Inputs</dt><dd>${b.inputs.map(esc).join(", ") || "none"}</dd><dt>Tracking pixels</dt><dd>${b.tracking_pixels}</dd><dt>Images</dt><dd>${b.images.length}</dd><dt>HTML size</dt><dd>${b.html_length} B</dd></dl><h3 style="margin-top:12px">Body (text as received)</h3><pre>${esc(b.text_preview || "(empty)")}</pre></div></div></div>`; },
    () => { const io = r.iocs; const row = (k, v) => v && (Array.isArray(v) ? v.length : true) ? `<tr><td style="color:var(--mut);white-space:nowrap">${k}</td><td class="mono" style="word-break:break-all">${Array.isArray(v) ? v.map(x => esc(typeof x === "object" ? `${x.name}: ${x.sha256}` : x)).join("<br>") : esc(v)}</td></tr>` : ""; return `<div class="card"><div class="hd"><h2>Indicators of Compromise</h2>${adhoc ? "" : `<a class="btn sm" href="/api/cases/${c.id}/iocs.csv">Export CSV</a>`}</div><table>${row("Sender", io.sender)}${row("Reply-To", io.reply_to)}${row("Return-Path", io.return_path)}${row("Origin IP", io.origin_ip)}${row("All relay IPs", io.ips)}${row("Domains", io.domains)}${row("URLs", io.urls)}${row("Attachment hashes", io.attachment_hashes)}${row("Crypto wallets", io.crypto_wallets)}${row("UPI IDs", io.upi_ids)}${row("Phone numbers", io.phones)}${row("Message-ID", io.message_id)}</table>${c.indicators?.length ? `<h3 style="margin-top:14px">Correlation keys stored for campaign clustering</h3><div class="chip-row">${c.indicators.map(i => `<span class="tag">${esc(i.type)}: ${esc(i.value)}</span>`).join("")}</div>` : ""}</div>`; },
    () => `<div class="card pad0"><div style="padding:14px 16px 10px"><h2 style="margin:0">Relationship graph — this email</h2><div class="mini" style="margin-top:4px">Sender, reply-to, relay IPs, ASNs, link domains, attachments and payment rails extracted from the message. Hover to highlight a relationship, click to isolate a node, drag to rearrange.</div></div><div class="graph-wrap" id="cg"></div></div>`,
    () => `<div class="card"><div class="hd"><h2 style="margin:0">Forensic timeline</h2><span class="mini">only real timestamps: header dates, RDAP registration dates, relay hops, analysis and custody events</span></div>${forensicTimeline(c)}</div>`,
    () => `<div class="grid g2"><div class="card"><h2>Forensic report</h2><p class="mini">Structured PDF for institutional action, legal review and LEA hand-off: verdict, authentication table, transmission path, geolocation & registry intel, findings, IOCs, recommended actions, related cases and chain of custody.</p>${adhoc ? '<div class="mini">Save the case (enable "save as case") to export reports.</div>' : `<div style="display:flex;gap:8px;flex-wrap:wrap"><a class="btn p" href="/api/cases/${c.id}/report.pdf" target="_blank">📄 Open PDF report</a><a class="btn" href="/api/cases/${c.id}/report.json" target="_blank">JSON</a><a class="btn" href="/api/cases/${c.id}/evidence.eml">Original .eml</a><button class="btn" id="verify">Verify evidence hash</button></div><div id="verify-out" class="mini" style="margin-top:8px"></div>
      <h3 style="margin-top:16px">Case management</h3><div style="display:flex;gap:8px;align-items:center;margin-bottom:8px"><select id="status"><option ${c.status === "open" ? "selected" : ""}>open</option><option ${c.status === "investigating" ? "selected" : ""}>investigating</option><option ${c.status === "confirmed" ? "selected" : ""}>confirmed</option><option ${c.status === "false_positive" ? "selected" : ""}>false_positive</option><option ${c.status === "closed" ? "selected" : ""}>closed</option></select><input type="text" id="tags" placeholder="tags, comma separated" value="${esc((c.tags || []).join(", "))}" style="flex:1"></div><textarea id="notes" style="min-height:90px" placeholder="Analyst notes (logged to custody)">${esc(c.analyst_notes || "")}</textarea><div style="margin-top:8px"><button class="btn p" id="save">Save</button></div>`}</div>
      <div class="card"><h2>Chain of custody</h2><div class="mini" style="margin-bottom:8px">Evidence SHA-256 <code>${esc(r.sha256)}</code> · immutable read-only copy at ingestion · every view / export / annotation logged.</div><div class="custody">${(c.custody || []).map(x => `<div><span class="mini">${esc(x.ts)}</span><span>${esc(x.actor)}</span><span class="badge b-mut">${esc(x.action)}</span><span class="mini">${esc(x.detail)}</span></div>`).join("") || '<div class="mini">—</div>'}</div></div></div>`,
  ];
  const showTab = i => {
    document.querySelectorAll(".tabs button").forEach(b => b.classList.toggle("active", +b.dataset.t === i));
    disposeVisuals();
    $("#tab").innerHTML = panes[i]();
    if (i === 1) {
      const gd = globeDataFromResult(r);
      const note = $("#globe-case-note");
      if (note && !gd.points.length) note.textContent = "No relay IP in this message has geolocation coordinates — nothing to plot (location data is never guessed).";
      mountGlobe($("#globe-case"), gd, {
        fallbackHtml: `<div style="padding:6px 14px 14px">${worldMap(r.trace_path, {dest: {lat: 21.17, lon: 72.83, label: "recipient (Surat, IN)"}})}</div>`,
        focus: gd.points.find(p => p.trust === "origin") || gd.points[0]
      });
    }
    if (i === 5) {
      const wrap = $("#cg");
      if (window.MTGraph) mountGraph(wrap, r.graph, {});
      else forceGraph(wrap, r.graph);
    }
    if (i === 7 && !adhoc) {
      $("#verify").onclick = async () => { const v = await api(`/api/cases/${c.id}/verify`); $("#verify-out").innerHTML = v.ok ? `<span style="color:#86efac">✓ Evidence intact — stored hash matches ${esc(v.stored_sha256)}</span>` : `<span style="color:#fca5a5">✗ TAMPER ALERT — ${esc(JSON.stringify(v))}</span>`; };
      $("#save").onclick = async () => { await api(`/api/cases/${c.id}`, {method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify({status: $("#status").value, notes: $("#notes").value, tags: $("#tags").value.split(",").map(x => x.trim()).filter(Boolean)})}); toast("Case updated", "logged to chain of custody"); routes.case(c.id); };
    }
  };
  document.querySelectorAll(".tabs button").forEach(b => b.onclick = () => showTab(+b.dataset.t));
  showTab(0);
}

function recommendations(r) {
  const a = r.attribution, s = r.score, h = r.headers, g = a.origin_geo || {}, reg = r.origin_ip_registry || {}, out = [];
  const th = [r.threat.primary, ...r.threat.secondary];
  if (["malicious", "likely_malicious"].includes(s.verdict)) { out.push("Quarantine organisation-wide (search by Message-ID / subject / sender) and purge before user interaction."); out.push("Block sender address, sender domain and all link domains at mail gateway, proxy and DNS resolver."); }
  if (th.includes("credential_phishing") || th.includes("spoofing")) out.push("Identify users who clicked/submitted (proxy + IdP sign-in logs); force password reset, revoke sessions, enforce MFA.");
  if (th.includes("business_email_compromise")) out.push("Alert Finance: verify any pending payment / beneficiary change out-of-band. If money moved, report within the golden hour to 1930 / cybercrime.gov.in and the beneficiary bank for a freeze.");
  if (th.includes("malware_delivery")) out.push("Detonate attachments in sandbox; hunt endpoints for the SHA-256 hashes; isolate hosts that opened them.");
  if (a.scenario === "compromised_account") out.push(`Treat ${h.from.address} as compromised — notify domain owner's IT, rotate credentials, review mailbox rules; request auth logs for ${a.origin_ip}.`);
  if (a.scenario === "attacker_owned_lookalike_domain") out.push(`Registrar abuse / UDRP takedown for ${h.from.registered_domain}; request registrant data via lawful request; snapshot DNS/WHOIS.`);
  if (a.scenario === "freemail_account") out.push(`Preservation + subscriber-info request to ${h.from.registered_domain} for ${h.from.address}: registration IP, recovery phone/email, login IP history.`);
  if (reg.abuse_contacts?.length) out.push(`Abuse report + log preservation to network owner of ${a.origin_ip}: ${reg.abuse_contacts.join(", ")} (${reg.netname || ""}, ${reg.rir || ""}).`);
  if ((g.tags || []).some(t => /TOR|PROXY|VPN/.test(t))) out.push("Origin is anonymised — pivot on reply-to, payment rails (UPI/bank/crypto), phone numbers and landing-page hosting rather than geolocation.");
  if (r.iocs.upi_ids?.length || r.iocs.phones?.length) out.push("UPI IDs / phone numbers are strong identity pivots: request KYC from PSP/bank and CAF from telecom operator via nodal officer.");
  if (["clean", "low_risk"].includes(s.verdict)) return ["No action required — authenticated and content appears benign. Retained for baseline modelling."];
  out.push("Circulate a sanitised awareness note to the targeted user group; add lure to phishing-simulation library.");
  return out;
}

/* Mail Accounts: Gmail/IMAP connection, per-account monitoring selection, startup catch-up
   and on-demand scans. Implemented in lib/console.js; all state comes from /api/monitor. */
routes.accounts = () => (window.MTConsole ? window.MTConsole.accounts() : (location.hash = "#/dashboard"));

routes.cases = async (arg = "") => {
  const qs = new URLSearchParams((location.hash.split("?")[1] || ""));
  window._caseJob = qs.get("job") || "";
  const render = async () => {
    const q = $("#q")?.value || "", v = $("#v")?.value || "";
    const src = $("#src")?.value || "";
    const cases = await api(`/api/cases?q=${encodeURIComponent(q)}&verdict=${v}&source=${src}&job=${encodeURIComponent(window._caseJob)}&limit=500${mbQ("&")}`);
    const srcIcon = c => ({imap: "📥", import: "🗂", sample: "🧪", upload: "⬆", batch: "⬆"}[c.source] || "");
    $("#tbl").innerHTML = cases.length ? `<table><thead><tr><th>Score</th><th>Subject / sender</th><th>Verdict · threat</th><th>Scenario</th><th>Origin</th><th>Campaign</th><th>Mailbox</th><th>Status</th><th>Analysed</th></tr></thead><tbody>${cases.map(c => `<tr class="row" onclick="location.hash='#/case/${c.id}'"><td><b style="color:${scoreColor(c.score)};font-size:15px">${Math.round(c.score)}</b></td><td><span class="ell">${esc(c.subject)}</span><span class="ell mini">${esc(c.sender)}</span></td><td>${verdictBadge(c.verdict, c.verdict.replace("_", " "))}<br><span class="mini">${esc(c.threat.replace(/_/g, " "))}</span></td><td class="mini">${esc((c.scenario || "").replace(/_/g, " "))}</td><td>${c.origin_country ? `${esc(c.origin_city || "")} ${esc(c.origin_country)}` : "—"}<br><span class="mini mono">${esc(c.origin_ip || "")}</span></td><td>${c.campaign_id ? `<a href="#/campaigns">${c.campaign_id}</a>` : "—"}</td><td class="mini" title="${esc(c.source || "")} · ${esc(c.source_ref || "")}">${srcIcon(c)} <span class="ell" style="max-width:170px;display:inline-block;vertical-align:bottom">${esc(c.mailbox || c.source || "")}</span></td><td><span class="badge b-mut">${esc(c.status)}</span></td><td class="mini">${fmtTs(c.created_at)}</td></tr>`).join("")}</tbody></table><div class="mini" style="padding:8px 12px">${cases.length} case(s)${cases.length >= 500 ? " (showing first 500 — refine the search)" : ""}</div>` : `<div class="empty">No cases match.</div>`;
  };
  const bar = await mailboxBar(() => render());
  view.innerHTML = `<div class="page-head" data-reveal><div><div class="eyebrow">MailTrace AI</div><h1>Case Management</h1><div class="sub" style="margin:0">Searchable evidence store — every analysed email with immutable evidence, indicators and custody log.${window._caseJob ? ` Filtered to ingestion job <span class="mono">${esc(window._caseJob)}</span> · <a href="#/cases">clear</a>` : ""}</div></div></div>${bar}<div style="display:flex;gap:8px;margin-bottom:12px"><input type="text" id="q" placeholder="Search subject, sender, IP, domain, hash, UPI, phone…" style="flex:1"><select id="v"><option value="">all verdicts</option><option value="malicious">malicious</option><option value="likely_malicious">likely malicious</option><option value="suspicious">suspicious</option><option value="low_risk">low risk</option><option value="clean">clean</option></select><select id="src"><option value="">all sources</option><option value="imap">📥 mailbox (IMAP)</option><option value="import">🗂 bulk import</option><option value="upload">⬆ upload</option><option value="sample">🧪 demo</option></select></div><div class="card pad0" id="tbl"></div>`;
  $("#q").oninput = render; $("#v").onchange = render; $("#src").onchange = render; bindMailboxBar(() => routes.cases()); render();
};

routes.campaigns = async () => {
  const [camps, bar] = await Promise.all([api("/api/campaigns" + mbQ()), mailboxBar(() => routes.campaigns())]);
  view.innerHTML = `<div class="page-head" data-reveal><div><div class="eyebrow">MailTrace AI</div><h1>Campaign Correlation</h1><div class="sub" style="margin:0">Emails are clustered into campaigns when they share hard indicators — sender / reply-to address, sender domain, origin IP, link domain, attachment hash, crypto wallet, UPI ID or phone number (graph connected components).${mbGet() ? ` Showing campaigns that hit <b>${esc(mbGet())}</b>; emails from other mailboxes in the same campaign are listed greyed below them.` : ""}</div></div></div>${bar}
    ${camps.length ? `<div class="card pad0" style="margin-bottom:16px" data-reveal>
      <div style="padding:14px 16px 10px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <div><h2 style="margin:0">Campaign infrastructure map</h2>
        <div class="mini" style="margin-top:3px">campaigns → member emails → the indicators that cluster them · hover to isolate, click an email to open it</div></div>
        <span class="mini" id="camp-stats"></span></div>
      <div class="graph-wrap" id="camp-graph" style="height:460px"></div></div>` : ""}
    ${camps.length ? camps.map(c => `<div class="card" style="margin-bottom:14px"><div class="hd"><div><h2 style="margin:0">${esc(c.name)}</h2><div class="mini">${c.id} · ${c.member_count} emails${c.scoped_count ? ` (<b>${c.scoped_count}</b> in this mailbox)` : ""} · dominant threat: ${esc(c.threat.replace(/_/g, " "))} · updated ${fmtTs(c.updated_at)}</div></div><span class="badge b-critical">ACTIVE CAMPAIGN</span></div>
      <h3>Shared infrastructure</h3><div class="chip-row" style="margin-bottom:10px">${c.shared_indicators.map(i => `<span class="tag bad">${esc(i)}</span>`).join("")}</div>
      <table><thead><tr><th>Score</th><th>Subject</th><th>Sender</th><th>Target</th><th>Mailbox</th><th>Origin</th><th>Time</th></tr></thead><tbody>${c.members.map(m => `<tr class="row" style="${c.scoped_mailbox && m.mailbox !== c.scoped_mailbox ? "opacity:.45" : ""}" onclick="location.hash='#/case/${m.id}'"><td><b style="color:${scoreColor(m.score)}">${Math.round(m.score)}</b></td><td>${esc(m.subject)}</td><td class="mini">${esc(m.sender)}</td><td class="mini">${esc(m.recipient)}</td><td class="mini">${esc(m.mailbox || "")}</td><td class="mini">${esc(m.origin_ip || "")} ${esc(m.origin_country || "")}</td><td class="mini">${fmtTs(m.created_at)}</td></tr>`).join("")}</tbody></table>
      <div class="mini" style="margin-top:8px">Campaign-level view: ${c.members.length} recipients targeted across ${new Set(c.members.map(m => m.origin_ip)).size} origin IP(s) — treat as a coordinated operation; block all shared indicators together.</div></div>`).join("") : `<div class="empty">${mbGet() ? `No campaign has hit <b>${esc(mbGet())}</b> yet.` : "No campaigns yet. Analyse the demo corpus from the dashboard — it contains two multi-email campaigns (SBI KYC phishing across 3 emails/2 infrastructures, and CEO-fraud from one gmail account)."}</div>`}`;
  bindMailboxBar(() => routes.campaigns());
  // campaign → member → shared-indicator graph, built from the real correlation keys in the case store
  if (camps.length && window.MTGraph && $("#camp-graph")) {
    const nodes = [], edges = [], seen = new Set();
    const add = (id, type, label, extra) => {
      if (seen.has(id)) return; seen.add(id);
      nodes.push(Object.assign({ id: id, type: type, label: label }, extra || {}));
    };
    camps.forEach(c => {
      const cid = "campaign:" + c.id;
      add(cid, "campaign", c.name, { member_count: c.member_count });
      (c.shared_indicators || []).forEach(v => {
        const p = String(v).indexOf(":"), t = p > 0 ? v.slice(0, p) : "indicator";
        add(v, t, String(v).slice(p + 1).slice(0, 40));
        edges.push({ source: cid, target: v, rel: "shared" });
      });
      (c.members || []).forEach(m => {
        add("case:" + m.id, "email", (m.subject || "(no subject)").slice(0, 38), { score: m.score, case_id: m.id });
        edges.push({ source: cid, target: "case:" + m.id, rel: "member" });
      });
    });
    const st = $("#camp-stats");
    if (st) st.innerHTML = `<b style="color:var(--cy)">${camps.length}</b> campaigns · <b style="color:var(--crit)">${nodes.filter(n => n.type === "email").length}</b> emails`;
    mountGraph($("#camp-graph"), { nodes: nodes, edges: edges }, { onSelect: n => { if (n && n.case_id) location.hash = "#/case/" + n.case_id; } });
  }
  window.MTfx.reveal(view);
};

routes.graph = async () => {
  const bar = await mailboxBar(() => routes.graph());
  view.innerHTML = `
    <div class="page-head" data-reveal><div><div class="eyebrow">Cross-case correlation</div><h1>Link Analysis</h1>
    <div class="sub" style="margin:0">Emails (ring colour = risk) connected to the indicators they share. Hubs with many edges are campaign infrastructure. Hover a node to isolate its relationships, drag to rearrange, scroll to zoom.</div></div>
    <div style="display:flex;gap:8px"><a class="btn" href="#/campaigns">◈ Campaigns</a><a class="btn p" href="#/cases">▤ Cases</a></div></div>
    ${bar}
    <div class="card pad0" data-reveal>
      <div style="padding:14px 16px 10px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <div><h2 style="margin:0">Infrastructure graph</h2><div class="mini" id="gg-sub" style="margin-top:3px">loading…</div></div>
        <div style="display:flex;gap:8px;align-items:center"><span class="mini" id="gg-stats"></span></div>
      </div>
      <div class="graph-wrap" id="gg" style="height:560px"><div class="loading"><div class="spin"></div> Building graph…</div></div>
    </div>`;
  bindMailboxBar(() => routes.graph());
  const data = await api("/api/graph" + mbQ());
  const wrap = $("#gg");
  if (!data.nodes.length) {
    wrap.innerHTML = `<div class="empty">No data yet — analyse some emails first.</div>`;
    return;
  }
  wrap.innerHTML = "";
  const sub = $("#gg-sub"), stats = $("#gg-stats");
  if (sub) sub.textContent = `${data.nodes.length} nodes · ${data.edges.length} relationships · shared-indicator correlation`;
  if (stats) stats.innerHTML = `<b style="color:var(--cy)">${data.nodes.filter(n => n.type === "email").length}</b> emails linked`;
  if (window.MTGraph) mountGraph(wrap, data, { onSelect: n => { if (n && n.type === "email" && n.case_id) location.hash = "#/case/" + n.case_id; } });
  else forceGraph(wrap, data, n => { if (n.type === "email") location.hash = "#/case/" + n.case_id; });
  window.MTfx.reveal(view);
};


/* ------------------------------------------------------------ mailboxes overview: one card per mail ID / import file */
routes.mailboxes = async () => {
  view.innerHTML = `<div class="loading"><div class="spin"></div> Loading mailboxes…</div>`;
  const [list, srcs] = await Promise.all([mailboxes(true), api("/api/sources").catch(() => [])]);
  const byUser = {}; srcs.forEach(s => { byUser[s.username] = s; });
  const tot = list.reduce((a, m) => a + m.total, 0), mal = list.reduce((a, m) => a + m.malicious, 0);
  const kind = m => m.source === "imap" ? "IMAP mailbox" : m.source === "import" ? "mailbox export" : m.source === "sample" ? "demo corpus" : "manual uploads";
  view.innerHTML = `<div class="page-head" data-reveal><div><div class="eyebrow">MailTrace AI</div><h1>Mailboxes</h1><div class="sub" style="margin:0">Every mail ID and import file that has analysed emails — pick one to scope Dashboard, Cases, Campaigns and Link Analysis to that mailbox only. ${list.length} mailbox(es) · ${tot} emails · <b style="color:var(--crit)">${mal}</b> malicious.</div></div>
    <div style="display:flex;gap:8px">${mbGet() ? `<button class="btn" id="mb-all">✕ Show all mailboxes</button>` : ""}<a class="btn p" href="#/sources">⇊ Connect another mailbox</a></div></div>
    ${list.length ? `<div class="grid g3" id="mb-grid">${list.map(m => { const s = byUser[m.mailbox]; const active = m.mailbox === mbGet(); const pct = m.total ? Math.round(100 * m.malicious / m.total) : 0; return `<div class="card mbcard ${active ? "on" : ""}" data-mb="${esc(m.mailbox)}">
        <div class="hd" style="margin-bottom:6px"><div style="min-width:0"><div class="t ell" title="${esc(m.mailbox)}">${mbIcon(m)} ${esc(m.mailbox)}</div><div class="mini">${kind(m)}${s ? ` · ${esc(s.host)} · ${{once: "manual", monitor: `monitor ${s.interval_min} min`, idle: "IDLE live"}[s.mode] || s.mode}` : ""}</div></div>${active ? `<span class="badge b-ok">selected</span>` : ""}</div>
        <div class="mbk"><div><b>${m.total}</b><span>emails</span></div><div><b style="color:var(--crit)">${m.malicious}</b><span>malicious</span></div><div><b style="color:var(--med)">${m.suspicious}</b><span>suspicious</span></div><div><b style="color:var(--acc)">${m.campaigns}</b><span>campaigns</span></div></div>
        <div class="mbbar2"><i style="width:${pct}%"></i></div><div class="mini">${pct}% of this mailbox is malicious · ${m.open_high} open high-risk · first ${fmtTs(m.first_at)} · last ${fmtTs(m.last_at)}</div>
        <div class="a" style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap"><button class="btn sm p" data-open="cases">▤ Cases</button><button class="btn sm" data-open="campaigns">◈ Campaigns</button><button class="btn sm" data-open="dashboard">▦ Dashboard</button>${s ? `<button class="btn sm" data-fetch="${esc(s.id)}">↻ New only</button>` : ""}</div></div>`; }).join("")}</div>` : `<div class="empty">No analysed emails yet. <a href="#/sources">Connect a mailbox or import an export</a> first.</div>`}`;
  const all = $("#mb-all"); if (all) all.onclick = () => { mbSet(""); routes.mailboxes(); };
  document.querySelectorAll(".mbcard").forEach(card => {
    const mb = card.dataset.mb;
    card.querySelectorAll("[data-open]").forEach(b => b.onclick = e => { e.stopPropagation(); mbSet(mb); location.hash = "#/" + b.dataset.open; });
    card.querySelectorAll("[data-fetch]").forEach(b => b.onclick = e => { e.stopPropagation(); sourceAction("incremental", b.dataset.fetch); });
    card.onclick = () => { mbSet(mb); location.hash = "#/cases"; };
  });
};

/* ------------------------------------------------------------ bulk ingestion: jobs + mail sources */
window._jobQuiet = true;
const _jobs = {};
function onJobEvent(j) {
  _jobs[j.id] = j;
  const active = Object.values(_jobs).filter(x => ["queued", "running", "fetching"].includes(x.status));
  const nb = $("#nav-jobs"); if (nb) { nb.hidden = !active.length; nb.textContent = active.length ? `${active.reduce((a, x) => a + x.analysed, 0)}/${active.reduce((a, x) => a + (x.total || 0), 0) || "…"}` : ""; }
  const el = document.getElementById("job-" + j.id); if (el) el.outerHTML = jobCard(j);
  else { const box = $("#jobs-live"); if (box) box.insertAdjacentHTML("afterbegin", jobCard(j)); }
}
const fmtDur = s => s == null ? "—" : s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
function jobCard(j) {
  const tot = Math.max(j.total || 0, j.fetched || 0, 1);
  const done = (j.analysed || 0) + (j.duplicates || 0) + (j.errors || 0);
  const pTri = Math.min(100, done / tot * 100), pMal = Math.min(pTri, (j.malicious || 0) / tot * 100);
  const enrT = j.enrich_total || 0, pEnr = enrT ? Math.min(100, (j.enriched || 0) / enrT * 100) : (j.phase === "finished" ? 100 : 0);
  const running = ["queued", "running", "fetching"].includes(j.status);
  const phase = j.status === "fetching" ? "fetching from mailbox…" : j.phase === "triage" ? "phase 1/2 · triage (no network, provisional scores)" : j.phase === "enrich" ? `phase 2/2 · live enrichment worst-first (${j.enriched}/${enrT})` : j.status;
  return `<div class="job" id="job-${j.id}"><div class="h"><b title="${esc(j.label)}">${j.kind === "imap" ? "📥" : "🗂"} ${esc(j.label)}</b><span style="display:flex;gap:6px;align-items:center"><span class="badge b-${esc(j.status)}">${esc(j.status)}</span>${running ? `<button class="btn sm" onclick="cancelJob('${j.id}')">Stop</button>` : `<a class="btn sm" href="#/cases?job=${j.id}">Cases</a>`}</span></div>
    <div class="pb" title="triage progress"><i class="mal" style="width:${pMal}%"></i><i style="width:${Math.max(0, pTri - pMal)}%"></i></div>
    ${enrT || j.phase === "enrich" ? `<div class="pb" title="enrichment progress"><i class="e" style="width:${pEnr}%"></i></div>` : ""}
    <div class="s"><span>${esc(phase)}</span><span><b>${done}</b>/${j.total || (running ? "?" : done)} processed${!running && j.analysed === 0 && j.duplicates > 0 ? " · all already analysed" : ""}</span><span><b style="color:var(--crit)">${j.malicious}</b> malicious</span><span><b style="color:var(--med)">${j.suspicious}</b> suspicious</span><span>${j.duplicates} dup</span><span>${j.errors} err</span>${j.rate_per_min ? `<span>${Math.round(j.rate_per_min)}/min</span>` : ""}${running && j.eta_s != null ? `<span>ETA ${fmtDur(j.eta_s)}</span>` : ""}${!running && j.started_at && j.finished_at ? `<span>took ${fmtDur(Math.round((new Date(j.finished_at) - new Date(j.started_at)) / 1000))}</span>` : ""}${j.error ? `<span style="color:var(--crit)">${esc(j.error)}</span>` : ""}</div></div>`;
}
window.cancelJob = async id => { try { await api(`/api/jobs/${id}/cancel`, {method: "POST"}); toast("Stopping job", id); } catch (e) { toast("Error", e.message, true); } };

const PROVIDERS = {
  gmail: {name: "Gmail / Google Workspace", host: "imap.gmail.com", port: 993, auth: "password", folders: "INBOX, [Gmail]/Spam", tip: "Google account → Security → 2-Step Verification ON → <b>App passwords</b> → create one for “Mail” and paste it here (your normal password will NOT work). Gmail IMAP must be enabled in Gmail settings → Forwarding and POP/IMAP."},
  outlook: {name: "Outlook.com / Microsoft 365", host: "outlook.office365.com", port: 993, auth: "oauth2", folders: "INBOX, Junk Email", tip: "Microsoft removed password login for IMAP. Use <b>auth = OAuth2</b> and paste an access token with scope <code>https://outlook.office.com/IMAP.AccessAsUser.All</code> (obtained via your tenant’s app registration / MSAL device-code flow)."},
  zoho: {name: "Zoho Mail", host: "imap.zoho.in", port: 993, auth: "password", folders: "INBOX, Spam", tip: "Zoho Mail → Settings → Mail Accounts → IMAP Access ON. With 2FA use an <b>application-specific password</b>."},
  yahoo: {name: "Yahoo", host: "imap.mail.yahoo.com", port: 993, auth: "password", folders: "INBOX, Bulk Mail", tip: "Yahoo Account Security → <b>Generate app password</b>."},
  nic: {name: "NIC / gov.in (Kavach)", host: "mail.gov.in", port: 993, auth: "password", folders: "INBOX", tip: "IMAP on NIC mail is subject to departmental policy and Kavach 2FA — obtain IT approval and an IMAP-enabled account first."},
  lab: {name: "Custom / institutional (Dovecot, Zimbra, Exchange)", host: "", port: 993, auth: "password", folders: "INBOX", tip: "Port 993 = IMAPS (TLS). Port 143 = STARTTLS. Use <b>plain-insecure</b> only for a lab server on your own machine."},
};

routes.sources = async () => {
  view.innerHTML = `<div class="loading"><div class="spin"></div> Loading mail sources…</div>`;
  const [srcs, jobs, health] = await Promise.all([api("/api/sources"), api("/api/jobs?limit=12"), api("/api/health")]);
  jobs.forEach(j => _jobs[j.id] = j);
  const desk = await desktopReady(300);
  view.innerHTML = `<div class="page-head" data-reveal><div><div class="eyebrow">MailTrace AI</div><h1>Mail Sources &amp; Bulk Ingestion</h1><div class="sub" style="margin:0">Stop downloading .eml files by hand. Connect a mailbox (read-only IMAP), drop a whole mailbox export, or point a phishing-report / journal mailbox at MailTrace — every message is deduplicated, sealed as evidence, custody-logged and analysed by ${health.ingest?.workers || 4} parallel workers.</div></div>
  <div class="steps3" style="margin:0 0 16px"><div><b>1 · Collect</b>IMAP <span class="mono">EXAMINE</span> + <span class="mono">BODY.PEEK[]</span> — identical bytes to an .eml, nothing on the server is marked read, moved or deleted. Or stream an .mbox / .zip export.</div><div><b>2 · Triage</b>Every message: SHA-256 dedupe → write-once evidence → header forensics + NLP + URL/attachment analysis with no network (~30 ms). 1,000 emails ≈ under a minute.</div><div><b>3 · Enrich</b>Live SPF/DKIM/DMARC, GeoIP, RDAP, Tor — worst provisional score first, through cached &amp; rate-limited resolvers. Campaigns re-cluster as results land.</div></div>
  <div class="grid g2" style="align-items:start">
    <div>
      <div class="card" style="margin-bottom:14px"><div class="hd"><h2>Connected mailboxes</h2><button class="btn sm p" id="src-new">＋ Connect mailbox</button></div>
        <div id="src-list">${srcs.length ? srcs.map(srcRow).join("") : `<div class="empty">No mailbox connected yet. Click <b>Connect mailbox</b> — a Gmail test account with an App Password takes two minutes.</div>`}</div></div>
      <div class="card" id="src-form-card" hidden></div>
      <div class="card" style="margin-bottom:14px"><h2>Bulk file import</h2><div class="mini" style="margin-bottom:8px">Whole-mailbox exports, no credentials needed: <b>.mbox</b> (Gmail → <a href="https://takeout.google.com" target="_blank">Google Takeout</a> → Mail; Thunderbird → ImportExportTools; Apple Mail → Export Mailbox), a <b>.zip</b> of .eml / .msg files, or hundreds of .eml selected at once. Files stream to disk — a 2 GB Takeout is fine.</div>
        <div class="drop sm" id="bdrop"><b>Drop .mbox / .zip / .eml files here</b><div class="mini">or click to browse${desk ? " · desktop: pick files or a whole folder" : ""}</div><input type="file" id="bfile" accept=".mbox,.mbx,.zip,.eml,.msg,.txt" multiple hidden></div>
        <div style="display:flex;gap:14px;align-items:center;margin-top:8px;flex-wrap:wrap"><label class="mini"><input type="checkbox" id="b-unwrap" checked> unwrap “forward as attachment” / journal wrappers</label><label class="mini">deep-enrich only if provisional score ≥ <input type="number" id="b-min" value="0" min="0" max="100" style="width:56px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:6px;padding:3px 6px"> (raise to 35 for 10k+ mailboxes)</label>${desk ? `<button class="btn sm" id="b-folder">Import folder…</button>` : ""}</div>
        <div id="bprog" style="margin-top:8px"></div></div>
    </div>
    <div>
      <div class="card" style="margin-bottom:14px"><div class="hd"><h2>Ingestion jobs</h2><span class="mini">${health.ingest?.workers || 4} workers · monitor ${health.ingest?.monitor ? "running" : "off"}</span></div><div id="jobs-live">${jobs.length ? jobs.map(jobCard).join("") : `<div class="mini">No jobs yet.</div>`}</div></div>
      <div class="card"><h2>Report-mailbox pattern (organisation-wide)</h2><div class="mini">Real SOCs don’t ask users to export anything: users press <b>Forward as attachment</b> (Outlook: More → Forward as Attachment · Gmail: ⋮ → Forward as attachment) to <span class="mono">phish-report@your-org</span>; or the mail admin adds a <b>journaling / BCC rule</b> that copies every inbound message to <span class="mono">mail-journal@your-org</span>. Connect that ONE mailbox here in <b>monitor</b> mode — MailTrace unwraps the attached original (headers intact) and scores it within seconds of arrival. Inline forwards lose the original headers and cannot be traced; the UI flags them.</div>
        <div class="tip" style="margin-top:10px"><b>Legal / privacy.</b> Only connect mailboxes you own or are explicitly authorised to monitor (IT Act 2000 §43/§66; DPDP Act 2023). Record the authorisation in the source — it is written to the chain of custody of every case that comes from it. Bodies never leave this machine; only IPs/domains are sent to enrichment services (disable in Settings → Offline mode).</div></div>
    </div>
  </div>`;
  $("#src-new").onclick = () => showSourceForm();
  document.querySelectorAll("[data-src-act]").forEach(b => b.onclick = () => sourceAction(b.dataset.srcAct, b.dataset.id));
  // bulk import drop zone
  const drop = $("#bdrop"), file = $("#bfile");
  const upload = async files => {
    if (!files.length) return;
    const total = [...files].reduce((a, f) => a + f.size, 0);
    $("#bprog").innerHTML = `<div class="loading"><div class="spin"></div> Uploading ${files.length} file(s) · ${(total / 1048576).toFixed(1)} MB…</div>`;
    const b = new FormData(); [...files].forEach(f => b.append("files", f)); b.append("unwrap", $("#b-unwrap").checked); if (parseFloat($("#b-min").value) > 0) b.append("deep_min_score", $("#b-min").value);
    try { const j = await api("/api/import/upload", {method: "POST", body: b}); $("#bprog").innerHTML = ""; onJobEvent(j); toast("Import started", `${j.label} → job ${j.id}`); } catch (e) { $("#bprog").innerHTML = `<div class="card" style="border-color:var(--crit)">Error: ${esc(e.message)}</div>`; }
  };
  drop.onclick = async () => desk ? desktopImportPick(false) : file.click();
  ["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => upload(e.dataTransfer.files));
  file.onchange = () => upload(file.files);
  if (desk) $("#b-folder").onclick = () => desktopImportPick(true);
};
window.desktopImportPick = desktopImportPick;
async function desktopImportPick(folder) {
  try {
    const paths = folder ? await window.pywebview.api.pick_folder() : await window.pywebview.api.pick_import_files();
    if (!paths || !paths.length) return;
    const j = await api("/api/import/path", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({paths, unwrap: $("#b-unwrap").checked, deep_min_score: parseFloat($("#b-min").value) > 0 ? parseFloat($("#b-min").value) : null})});
    onJobEvent(j); toast("Import started", `${j.label} → job ${j.id}`);
  } catch (e) { toast("Import failed", e.message, true); }
}
function srcRow(s) {
  const st = s.state || {}; const seen = Object.entries(st).filter(([k]) => k.startsWith("last_uid:")).map(([k, v]) => `${k.slice(9)} ≤ uid ${v}`).join(" · ");
  const mode = {once: "manual", monitor: `monitor every ${s.interval_min} min`, idle: "IDLE push · live"}[s.mode] || s.mode;
  return `<div class="src" id="src-${s.id}"><div><div class="t">${esc(s.name)} <span class="badge b-mut">${esc(s.kind)}</span><span class="badge ${s.enabled ? "b-ok" : "b-mut"}">${s.enabled ? mode : "disabled"}</span>${s.last_error ? `<span class="badge b-high" title="${esc(s.last_error)}">error</span>` : ""}</div>
    <div class="m mono">${esc(s.username)} @ ${esc(s.host)}:${s.port} · ${esc(s.auth)} · folders ${esc((s.folders || []).join(", "))}${s.since ? ` · since ${esc(s.since)}` : ""}</div>
    <div class="m">${s.last_run ? `last run ${fmtTs(s.last_run)}` : "never run"}${seen ? ` · ${seen}` : ""}${s.authorization ? ` · authorised: ${esc(s.authorization)}` : ""}${s.last_error ? `<div style="color:var(--high)">${esc(s.last_error)}</div>` : ""}</div></div>
    <div class="a"><button class="btn sm p" data-src-act="backfill" data-id="${s.id}" title="Fetch everything since the configured date">▶ Fetch all</button><button class="btn sm" data-src-act="incremental" data-id="${s.id}" title="Only messages newer than the last fetched UID">↻ New only</button><button class="btn sm" data-src-act="test" data-id="${s.id}">Test</button><button class="btn sm" data-src-act="edit" data-id="${s.id}">Edit</button><button class="btn sm danger" data-src-act="delete" data-id="${s.id}">✕</button></div></div>`;
}
async function sourceAction(act, id) {
  try {
    if (act === "delete") { if (!confirm("Remove this mail source? Already-imported cases are kept.")) return; await api(`/api/sources/${id}`, {method: "DELETE"}); return routes.sources(); }
    if (act === "edit") { const s = (await api("/api/sources")).find(x => x.id === id); return showSourceForm(s); }
    if (act === "test") { toast("Testing connection…", id); const r = await api(`/api/sources/test?sid=${id}`, {method: "POST", headers: {"Content-Type": "application/json"}, body: "{}"}); return toast(r.ok ? "Connection OK" : "Connection failed", r.ok ? `${r.total} messages in ${Object.keys(r.counts).join(", ")} · ${r.ms} ms${r.idle ? " · IDLE supported" : ""}` : r.error, !r.ok); }
    const j = await api(`/api/sources/${id}/run`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({mode: act})}); onJobEvent(j); toast("Fetch started", `${j.label} → ${j.id}`);
  } catch (e) { toast("Error", e.message, true); }
}
function showSourceForm(s = null) {
  const card = $("#src-form-card"); card.hidden = false;
  const p = s ? null : PROVIDERS.gmail;
  card.innerHTML = `<div class="hd"><h2>${s ? "Edit mailbox" : "Connect a mailbox"}</h2><button class="btn sm" id="sf-close">✕</button></div>
    ${s ? "" : `<div class="prov">${Object.entries(PROVIDERS).map(([k, v]) => `<button data-p="${k}">${esc(v.name)}</button>`).join("")}</div>`}
    <div class="tip" id="sf-tip">${p ? p.tip : ""}</div>
    <div class="form" style="margin-top:10px">
      <div><label>Display name</label><input type="text" id="sf-name" value="${esc(s?.name || "")}" placeholder="e.g. Cyber Cell phish-report mailbox"></div>
      <div><label>Authorisation (who approved monitoring)</label><input type="text" id="sf-auth" value="${esc(s?.authorization || "")}" placeholder="e.g. own test account / CISO memo #123"></div>
      <div><label>IMAP host</label><input type="text" id="sf-host" value="${esc(s?.host || p?.host || "")}"></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px"><div><label>Port</label><input type="number" id="sf-port" value="${s?.port || p?.port || 993}"></div><div><label>Auth</label><select id="sf-authm"><option value="password" ${(s?.auth || p?.auth) === "password" ? "selected" : ""}>password / app password</option><option value="oauth2" ${(s?.auth || p?.auth) === "oauth2" ? "selected" : ""}>OAuth2 (XOAUTH2 token)</option><option value="plain-insecure" ${(s?.auth) === "plain-insecure" ? "selected" : ""}>plain (lab server, no TLS)</option></select></div></div>
      <div><label>Username / email</label><input type="text" id="sf-user" value="${esc(s?.username || "")}" placeholder="you@gmail.com"></div>
      <div><label>${s?.has_secret ? "App password / token (leave blank to keep)" : "App password / token"}</label><input type="password" id="sf-secret" autocomplete="new-password"></div>
      <div><label>Folders (comma separated)</label><input type="text" id="sf-folders" value="${esc(s ? (s.folders || []).join(", ") : p.folders)}"></div>
      <div><label>Only messages since</label><input type="date" id="sf-since" value="${esc(s?.since || new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 10))}"></div>
      <div><label>Mode</label><select id="sf-mode"><option value="once" ${(s?.mode || "once") === "once" ? "selected" : ""}>manual — fetch when I click</option><option value="monitor" ${s?.mode === "monitor" ? "selected" : ""}>monitor — poll for new mail</option><option value="idle" ${s?.mode === "idle" ? "selected" : ""}>IDLE — push notification (if server supports)</option></select></div>
      <div><label>Poll interval (minutes)</label><input type="number" id="sf-int" value="${s?.interval_min || 5}" min="1"></div>
      <div class="w"><label style="text-transform:none;font-size:12px;color:var(--txt)"><input type="checkbox" id="sf-unwrap" ${s ? (s.unwrap ? "checked" : "") : "checked"}> unwrap <i>forward-as-attachment</i> / journaling wrappers (report mailboxes)</label></div>
      <div class="w" style="display:flex;gap:8px;align-items:center"><button class="btn" id="sf-test">Test connection</button><button class="btn p" id="sf-save">${s ? "Save changes" : "Save mailbox"}</button><span class="mini" id="sf-out"></span></div>
    </div>`;
  card.scrollIntoView({behavior: "smooth", block: "nearest"});
  const val = () => ({name: $("#sf-name").value.trim(), host: $("#sf-host").value.trim(), port: parseInt($("#sf-port").value) || 993, auth: $("#sf-authm").value, username: $("#sf-user").value.trim(), secret: $("#sf-secret").value || undefined,
    folders: $("#sf-folders").value.split(",").map(x => x.trim()).filter(Boolean), since: $("#sf-since").value || null, mode: $("#sf-mode").value, interval_min: parseInt($("#sf-int").value) || 5, unwrap: $("#sf-unwrap").checked, authorization: $("#sf-auth").value.trim()});
  card.querySelectorAll("[data-p]").forEach(b => b.onclick = () => { const v = PROVIDERS[b.dataset.p]; $("#sf-host").value = v.host; $("#sf-port").value = v.port; $("#sf-authm").value = v.auth; $("#sf-folders").value = v.folders; $("#sf-tip").innerHTML = v.tip; if (!$("#sf-name").value) $("#sf-name").value = v.name; });
  $("#sf-close").onclick = () => card.hidden = true;
  $("#sf-test").onclick = async () => { $("#sf-out").innerHTML = `<span class="spin" style="width:12px;height:12px;display:inline-block"></span> connecting…`; try { const r = await api(`/api/sources/test${s ? "?sid=" + s.id : ""}`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(val())}); $("#sf-out").innerHTML = r.ok ? `<span style="color:var(--ok)">✓ ${r.total} messages · folders: ${esc(r.folders.slice(0, 6).join(", "))}${r.folders.length > 6 ? "…" : ""} · ${r.ms} ms${r.idle ? " · IDLE" : ""}</span>` : `<span style="color:var(--crit)">✕ ${esc(r.error)}</span>`; } catch (e) { $("#sf-out").innerHTML = `<span style="color:var(--crit)">${esc(e.message)}</span>`; } };
  $("#sf-save").onclick = async () => { const v = val(); if (!v.host || !v.username) return toast("Host and username are required", "", true); if (!s && !v.secret) return toast("Enter the app password / token", "", true); try { await api(s ? `/api/sources/${s.id}` : "/api/sources", {method: s ? "PUT" : "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(v)}); toast("Mailbox saved", v.mode === "once" ? "Click ▶ Fetch all to import" : `Monitoring: ${v.mode}`); routes.sources(); } catch (e) { toast("Error", e.message, true); } };
}

routes.lookup = async () => {
  view.innerHTML = `<div class="page-head" data-reveal><div><div class="eyebrow">MailTrace AI</div><h1>IP / Domain Lookup</h1><div class="sub" style="margin:0">Ad-hoc enrichment: GeoIP · ASN · Tor · RDAP netblock & abuse contact · domain registration age · SPF / DMARC / MX.</div></div></div><div style="display:flex;gap:8px;margin-bottom:14px"><input type="text" id="lq" placeholder="e.g. 5.188.206.14 or sbi-kyc-verify.top" style="flex:1"><button class="btn p" id="lgo">Lookup</button></div><div id="lout"></div>`;
  const go = async () => { const q = $("#lq").value.trim(); if (!q) return; $("#lout").innerHTML = `<div class="loading"><div class="spin"></div></div>`; const isIp = /^[\d.]+$|:/.test(q); try { const r = await api(isIp ? `/api/lookup/ip/${q}` : `/api/lookup/domain/${q}`); $("#lout").innerHTML = `<div class="card"><h2>${esc(q)}</h2>${isIp ? `<dl class="kv"><dt>Location</dt><dd>${flag(r.countryCode)} ${esc(window.MTgeo ? window.MTgeo.place(window.MTgeo.precision(r)) : ([r.city, r.regionName, r.country].filter(Boolean).join(", ") || "—"))}</dd>
        <dt>Precision</dt><dd>${window.MTgeo ? window.MTgeo.badge(r) : "—"}</dd>
        <dt>Coordinates</dt><dd>${window.MTgeo ? window.MTgeo.coordsRow(r) : "—"}</dd>
        ${(r.geo_precision && r.geo_precision.caveat) ? `<dt>Caveat</dt><dd class="mini" style="color:var(--amber)">${esc(r.geo_precision.caveat)}</dd>` : ""}<dt>ISP / ASN</dt><dd>${esc(r.isp || "")} · ${esc(r.as || "")}</dd><dt>Class</dt><dd>${(r.tags || []).map(t => `<span class="tag">${esc(t)}</span>`).join("")} ${esc(r.category || "")}</dd><dt>PTR</dt><dd class="mono">${esc(r.ptr || "none")}</dd><dt>Tor exit</dt><dd>${r.is_tor ? "YES" : "no"}</dd><dt>RIR</dt><dd>${r.rdap?.found ? `${esc(r.rdap.netname)} · ${esc(r.rdap.rir)} · ${esc(r.rdap.country || "")} · ${esc(r.rdap.org || "")}` : "—"}</dd><dt>Abuse</dt><dd>${(r.rdap?.abuse_contacts || []).map(esc).join(", ") || "—"}</dd></dl>` : `<dl class="kv"><dt>Registered</dt><dd>${r.rdap.found ? `${esc((r.rdap.created || "").slice(0, 10))} (${r.rdap.age_days} days) · ${esc(r.rdap.registrar || "")}` : esc(r.rdap.note || "not found")}</dd><dt>Nameservers</dt><dd class="mono">${(r.rdap.nameservers || []).map(esc).join(", ") || "—"}</dd><dt>MX</dt><dd class="mono">${(r.mx || []).map(esc).join(", ") || "none"}</dd><dt>SPF</dt><dd class="mono">${esc(r.spf || "none")}</dd><dt>DMARC</dt><dd class="mono">${esc(r.dmarc?.record || "none")} ${r.dmarc?.policy ? `<span class="badge ${r.dmarc.policy === "reject" ? "b-ok" : r.dmarc.policy === "quarantine" ? "b-medium" : "b-high"}">p=${r.dmarc.policy}</span>` : ""}</dd></dl>`}<pre style="margin-top:10px">${esc(JSON.stringify(r, null, 2))}</pre></div>`; } catch (e) { $("#lout").innerHTML = `<div class="card">Error: ${esc(e.message)}</div>`; } };
  $("#lgo").onclick = go; $("#lq").onkeydown = e => e.key === "Enter" && go();
};

routes.settings = async () => {
  view.innerHTML = `<div class="loading"><div class="spin"></div> Loading settings…</div>`;
  const [s, h] = await Promise.all([api("/api/settings"), api("/api/health")]);
  const o = s.org, st = s.settings;
  const info = isDesktop() ? await window.pywebview.api.info() : null;
  view.innerHTML = `<div class="page-head" data-reveal><div><div class="eyebrow">MailTrace AI</div><h1>Settings</h1><div class="sub" style="margin:0">Tenant profile, enrichment mode and data management. Changes apply immediately — no restart needed.</div></div></div>
  <div class="grid g2">
    <div class="card"><h2>Organisation profile</h2><div class="mini" style="margin-bottom:10px">Used for spoofing / VIP-impersonation / partner checks. One entry per line.</div>
      <label class="mini">Organisation name</label><input type="text" id="s-org" value="${esc(o.organization || "")}" style="width:100%;margin:4px 0 10px">
      <label class="mini">Your email domains</label><textarea id="s-dom" style="min-height:64px">${esc((o.domains || []).join("\n"))}</textarea>
      <label class="mini">Trusted partner domains</label><textarea id="s-part" style="min-height:64px">${esc((o.partners || []).join("\n"))}</textarea>
      <label class="mini">VIPs — <span class="mono">Name | Role | email</span></label><textarea id="s-vip" style="min-height:90px">${esc((o.vips || []).map(v => `${v.name} | ${v.role || ""} | ${v.email}`).join("\n"))}</textarea>
      <label class="mini">Email service provider (google / microsoft / zoho / other)</label><input type="text" id="s-esp" value="${esc(o.esp || "")}" style="width:100%;margin:4px 0 10px">
      <button class="btn p" id="s-save-org">Save profile</button></div>
    <div>
      <div class="card" style="margin-bottom:14px"><h2>Enrichment & analyst</h2>
        <label style="display:flex;gap:8px;align-items:center;margin:8px 0"><input type="checkbox" id="s-off" ${st.offline ? "checked" : ""}> <span><b>Offline mode</b> — no live DNS / GeoIP / RDAP / Tor lookups (uses bundled seeds &amp; cache)</span></label>
        <div class="mini" style="margin-bottom:10px">Currently: <b>${s.offline_active ? "OFFLINE" : "live enrichment"}</b></div>
        <label class="mini">Default analyst identity (chain-of-custody actor)</label><input type="text" id="s-an" value="${esc(st.analyst || "")}" style="width:100%;margin:4px 0 10px">
        <label class="mini">Evidence retention (days)</label><input type="text" id="s-ret" value="${esc(st.retention_days ?? 180)}" style="width:100%;margin:4px 0 10px">
        <button class="btn p" id="s-save">Save settings</button></div>
      <div class="card" style="margin-bottom:14px"><h2>Data & storage</h2>
        <dl class="kv"><dt>Data folder</dt><dd class="mono" style="word-break:break-all">${esc(s.data_dir)}</dd><dt>Engine</dt><dd>Python ${esc(h.python)} · ${esc(h.platform)} · ${isDesktop() ? "desktop app" : "web"} v${esc(h.version || "")}</dd><dt>NLP model</dt><dd>${esc(h.model?.model || "")} · acc ${h.model?.accuracy ? (h.model.accuracy * 100).toFixed(1) + "%" : "?"} · ${esc(h.model_status?.backend || "")}</dd>${info ? `<dt>Log file</dt><dd class="mono" style="word-break:break-all">${esc(info.log)}</dd>` : ""}</dl>
        <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">${isDesktop() ? `<button class="btn" id="s-open-data">Open data folder</button><button class="btn" id="s-open-log">Open log</button>` : ""}<button class="btn danger" id="s-reset">Delete all cases &amp; evidence</button></div></div>
    </div>
  </div>`;
  $("#s-save-org").onclick = async () => {
    const lines = id => $(id).value.split("\n").map(x => x.trim()).filter(Boolean);
    const vips = lines("#s-vip").map(l => { const [name, role, email] = l.split("|").map(x => (x || "").trim()); return {name, role, email: email || role}; }).filter(v => v.name && v.email);
    try { await api("/api/org", {method: "PUT", headers: {"Content-Type": "application/json"}, body: JSON.stringify({organization: $("#s-org").value.trim(), domains: lines("#s-dom"), partners: lines("#s-part"), vips, esp: $("#s-esp").value.trim()})}); toast("Profile saved", "New analyses will use the updated tenant profile"); } catch (e) { toast("Error", e.message, true); }
  };
  $("#s-save").onclick = async () => {
    try { const r = await api("/api/settings", {method: "PUT", headers: {"Content-Type": "application/json"}, body: JSON.stringify({offline: $("#s-off").checked, analyst: $("#s-an").value.trim(), retention_days: parseInt($("#s-ret").value) || 180})}); if ($("#s-an").value.trim()) $("#analyst").value = $("#s-an").value.trim(); toast("Settings saved", r.offline_active ? "Offline mode is ON" : "Live enrichment is ON"); routes.settings(); } catch (e) { toast("Error", e.message, true); }
  };
  $("#s-reset").onclick = async () => {
    const yes = window.MTConsole
      ? await window.MTConsole.confirm({
          title: "Delete all case data?",
          body: "<p class='mini'>This removes every case, indicator, campaign, custody log and sealed evidence file from the evidence store. Connected mail accounts and their credentials are kept.</p>",
          ok: "Delete everything", danger: true })
      : confirm("Delete ALL cases, indicators, campaigns, custody logs and sealed evidence files? This cannot be undone.");
    if (!yes) return;
    try { const r = await api("/api/admin/reset", {method: "POST"}); toast("Case store reset", `${r.cases_deleted} cases · ${r.evidence_files_deleted} evidence files deleted`); } catch (e) { toast("Error", e.message, true); }
  };
  if (isDesktop()) { $("#s-open-data").onclick = () => window.pywebview.api.open_data_folder(); $("#s-open-log").onclick = () => window.pywebview.api.open_path(info.log); }
};

/* ------------------------------------------------------------ boot */
(async () => {
  const bootSay = t => { if (window.MTmotion) window.MTmotion.boot.label(t); };
  bootSay("connecting to analysis backend…");
  try { const h = await api("/api/health"); const m = h.model || {}; $("#model-info").textContent = `NLP: ${m.model || "?"} · acc ${m.accuracy ? (m.accuracy * 100).toFixed(1) + "%" : "?"} · AUC ${m.roc_auc || "?"}${h.offline ? " · OFFLINE" : ""}${h.desktop ? " · desktop" : ""}`;
    try { const s = await api("/api/settings"); if (s.settings?.analyst) $("#analyst").value = s.settings.analyst; } catch {}
    bootSay("detection engine ready");
    if (h.version) engineBanner(h.version);
  } catch { bootSay("backend unreachable — running offline"); }
  try {
    const mon = await api("/api/monitor");
    const badge = $("#nav-acc");
    if (badge) { badge.hidden = !mon.selected; badge.textContent = mon.selected || ""; }
    bootSay(mon.selected ? "checking " + mon.selected + " monitored account(s) for new mail" : "no account selected for monitoring");
  } catch { bootSay("older engine — mailbox monitoring unavailable"); }
  if (window.MTmotion) window.MTmotion.boot.end();
  if (window.MTConsole) {
    window.MTConsole.bind({ $, esc, api, toast, view, scoreColor, fmtTs, verdictBadge, routes, vtrack });
    window.MTConsole.refresh();
    const bellBtn = document.getElementById("mt-bell");
    if (bellBtn && window.Notification && Notification.permission === "default") {
      bellBtn.addEventListener("click", () => Notification.requestPermission().catch(() => {}), { once: true });
    }
  }
  mbSet(mbGet()); connectEvents(); navigate();
  // any [data-reveal] block added later (async routes) fades in when it scrolls into view
  if (window.MTfx) {
    const mo = new MutationObserver(() => window.MTfx.reveal(view));
    mo.observe(view, { childList: true, subtree: true });
  }
})();
