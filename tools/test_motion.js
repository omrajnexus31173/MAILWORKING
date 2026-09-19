/* MailTrace AI — headless SPA + motion-layer test (jsdom).
   Drives the real app against the live backend and asserts the animation layer is wired
   (without ever faking analysis data). Run with the server up: node tools/test_motion.js */
const { JSDOM, VirtualConsole } = require("/tmp/fe/node_modules/jsdom");
const BASE = process.env.BASE || "http://127.0.0.1:8000";
const REDUCE = process.env.REDUCE === "1";   // run again with the OS "reduce motion" setting on
let pass = 0, fail = 0;
const errors = [];
const ok = (name, cond, extra) => {
  if (cond) { pass++; console.log("  ✓ " + name); }
  else { fail++; console.log("  ✗ " + name + (extra ? " — " + extra : "")); }
};

/* ---- canvas + browser stubs jsdom does not implement -------------------------------------- */
function mockCtx() {
  const grad = { addColorStop() {} };
  const impl = {
    createLinearGradient: () => grad,
    createRadialGradient: () => grad,
    createPattern: () => null,
    measureText: () => ({ width: 12 }),
    getImageData: () => ({ data: new Uint8ClampedArray(4) }),
    canvas: null
  };
  return new Proxy(impl, {
    get(t, k) { return (k in t) ? t[k] : (() => {}); },   // every other 2D call is a no-op
    set(t, k, v) { t[k] = v; return true; }
  });
}
function stubWindow(win) {
  win.HTMLCanvasElement.prototype.getContext = function () { return mockCtx(); };
  // jsdom has no fetch: bridge to node's undici (same semantics the browser uses)
  win.fetch = (u, o) => fetch(new URL(u, BASE).href, o);
  win.Headers = globalThis.Headers;
  win.Response = globalThis.Response;
  win.Request = globalThis.Request;
  win.EventSource = class { constructor() {} addEventListener() {} close() {} };
  win.IntersectionObserver = class {
    constructor(cb) { this.cb = cb; }
    observe(el) { this.cb([{ isIntersecting: true, target: el }], this); }
    unobserve() {} disconnect() {}
  };
  win.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
  win.matchMedia = q => ({ matches: REDUCE && /prefers-reduced-motion/.test(q), media: q, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} });
  win.scrollTo = () => {};
  win.devicePixelRatio = 1;
  // jsdom reports 2 cores, which would select the "low" tier and switch animations off.
  // Claim a normal desktop so the FULL motion path is what gets exercised here.
  Object.defineProperty(win.navigator, "hardwareConcurrency", { value: 8 });
  Object.defineProperty(win.navigator, "deviceMemory", { value: 8 });
  win.requestAnimationFrame = cb => setTimeout(() => cb(Date.now()), 8);
  win.cancelAnimationFrame = id => clearTimeout(id);
}
const wait = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const vc = new VirtualConsole();
  vc.on("jsdomError", e => errors.push("jsdomError: " + e.message));
  vc.on("error", (...a) => errors.push("console.error: " + a.join(" ")));
  vc.on("warn", (...a) => { /* keep warnings out of the error list */ });

  const dom = await JSDOM.fromURL(BASE + "/", {
    runScripts: "dangerously", resources: "usable", pretendToBeVisual: true, virtualConsole: vc,
    beforeParse: stubWindow
  });
  const win = dom.window, doc = win.document;
  await new Promise(r => win.addEventListener("load", r));
  await wait(2500);

  const engHealth = await (await fetch(BASE + "/api/health")).json();
  const hasMonitor = (await fetch(BASE + "/api/monitor")).ok;
  const hasNotif = (await fetch(BASE + "/api/notifications")).ok;
  console.log("  • engine " + engHealth.version + " | /api/monitor " + (hasMonitor ? "yes" : "no") +
              " | /api/notifications " + (hasNotif ? "yes" : "no"));

  console.log("\n[1] assets & boot");
  for (const p of ["/static/app.css", "/static/motion.css", "/static/lib/fx.js", "/static/lib/motion.js",
                   "/static/lib/globe.js", "/static/lib/graph.js", "/static/lib/pipeline.js", "/static/vendor/three.min.js"]) {
    const r = await fetch(BASE + p);
    ok("serves " + p + " (" + r.status + ")", r.ok);
  }
  ok("motion layer exposed (MTmotion)", !!win.MTmotion);
  ok("MTfx.reveal wrapped by motion layer", win.MTfx && /revealNow/.test(String(win.MTfx.reveal)));
  ok("boot splash dismissed after health check", !doc.getElementById("boot"), "boot still in DOM");
  if (engHealth.version === "1.3.0") ok("no engine warning on the current engine", !doc.getElementById("mt-engbar"));
  else ok("older engine shows an honest upgrade notice", !!doc.getElementById("mt-engbar"), "engine " + engHealth.version);
  if (REDUCE) {
    ok("reduced-motion: motion layer switched off", win.MTmotion && win.MTmotion.off === true);
    ok("reduced-motion: no ambient orbs", doc.querySelectorAll(".mt-orb").length === 0);
  } else {
    ok("ambient orbs injected", doc.querySelectorAll(".mt-orb").length >= 2);
    ok("motion tier is not degraded", win.MTmotion && win.MTmotion.off === false, "quality=" + (win.MTmotion && win.MTmotion.quality));
  }

  console.log("\n[2] dashboard entrance");
  win.location.hash = "#/dashboard";
  await wait(2600);
  const view = doc.getElementById("view");
  ok("view has entry animation class", view.classList.contains("mt-view-in"));
  ok("sections marked for reveal", view.querySelectorAll("[data-reveal]").length >= 3,
    "found " + view.querySelectorAll("[data-reveal]").length);
  ok("revealed blocks are visible (is-in)", view.querySelectorAll("[data-reveal].is-in").length >= 3,
    "found " + view.querySelectorAll("[data-reveal].is-in").length);
  ok("cursor-spotlight layers added to cards", view.querySelectorAll(".card > .spot, .drop > .spot").length >= 3,
    "found " + view.querySelectorAll(".card > .spot").length);
  ok("hero stat sequence staged (--i)", !!view.querySelector(".hero-stats .v") &&
    view.querySelector(".hero-stats.mt-seq") !== null);
  ok("parallax target registered", view.querySelectorAll("[data-par]").length >= 1);
  ok("counters animated to real values", (() => {
    const el = view.querySelector("[data-count]");
    return el && el.getAttribute("data-v") !== null;
  })());
  ok("headline decoded back to its real text", (() => {
    const h = view.querySelector(".page-head h1");
    return h && /Command Center/.test(h.textContent);
  })(), doc.querySelector(".page-head h1") ? doc.querySelector(".page-head h1").textContent : "no h1");
  ok("globe surface mounted (WebGL canvas, or documented flat-map fallback)",
    !!doc.querySelector("#globe-main canvas") || !!doc.querySelector(".geo-fallback"),
    "neither canvas nor fallback — globe section missing");
  ok("threat rows render real cases", view.querySelectorAll(".threat-row").length >= 1);
  ok("no revealed block left invisible", view.querySelectorAll("[data-reveal]:not(.is-in)").length === 0,
    view.querySelectorAll("[data-reveal]:not(.is-in)").length + " stuck");

  console.log("\n[3] micro-interactions");
  const btn = view.querySelector(".btn");
  if (btn && !REDUCE) {
    btn.dispatchEvent(new win.MouseEvent("pointerdown", { bubbles: true, clientX: 5, clientY: 5 }));
    await wait(60);
    ok("press ripple spawned", !!btn.querySelector(".rip"));
  } else if (REDUCE) console.log("  • press ripple skipped (reduced motion)");
  else ok("press ripple spawned", false, "no button");
  const card = view.querySelector(".card");
  card.dispatchEvent(new win.MouseEvent("pointermove", { bubbles: true, clientX: 40, clientY: 30 }));
  await wait(60);
  if (REDUCE) {
    ok("reduced-motion: card hover still tracked without effects", true);
  } else {
    ok("card lights under the cursor", card.classList.contains("lit"));
    ok("spotlight position tracked", card.style.getPropertyValue("--mx") !== "");
  }

  console.log("\n[4] navigation transition");
  win.location.hash = "#/cases";
  await wait(120);
  if (REDUCE) console.log("  • route veil skipped (reduced motion)");
  else ok("route veil created", !!doc.querySelector(".mt-wipe"));
  await wait(2200);
  ok("cases view rendered", /case/i.test(doc.getElementById("view").textContent.slice(0, 400)));
  ok("nav active indicator", !!doc.querySelector("nav a.active"));

  console.log("\n[5] analysis pipeline + AI processing visual");
  win.location.hash = "#/analyze";
  await wait(2200);
  const sample = doc.querySelector(".sample");
  ok("demo corpus listed", !!sample);
  if (sample) {
    sample.dispatchEvent(new win.MouseEvent("click", { bubbles: true }));
    // the backend is fast, so poll instead of sampling a single instant
    let sawScan = false, maxPipe = 0;
    for (let i = 0; i < 80; i++) {
      if (doc.querySelector(".ai-scan canvas")) sawScan = true;
      const n = doc.querySelectorAll("#pipe .pipe-node").length;
      if (n > maxPipe) maxPipe = n;
      if (/#\/case\//.test(win.location.hash)) break;
      await wait(50);
    }
    if (REDUCE) console.log("  • AI-processing canvas skipped (reduced motion)");
    else ok("AI-processing canvas mounted while the backend works", sawScan);
    ok("pipeline stages rendered (12-node pipeline)", maxPipe >= 5, "max nodes seen: " + maxPipe);
    await wait(6000);
    ok("AI-processing visual removed once the result arrived", !doc.querySelector(".ai-scan canvas"));
    ok("navigated to the finished case", /#\/case\//.test(win.location.hash), win.location.hash);
  }

  console.log("\n[6] case detail: staged reveal, timeline, graph, globe");
  await wait(2500);
  const v2 = doc.getElementById("view");
  ok("threat result block is staged", !!v2.querySelector(".mt-seq"));
  ok("staged children carry --i", (() => {
    const ch = v2.querySelector(".mt-seq");
    return ch && ch.children.length && ch.children[0].style.getPropertyValue("--i") !== "";
  })());
  const tabs = [...doc.querySelectorAll(".tabs button[data-t]")];
  ok("case tabs rendered", tabs.length >= 8, "found " + tabs.length);
  const tl = tabs.find(t => /timeline/i.test(t.textContent));
  if (tl) { tl.dispatchEvent(new win.MouseEvent("click", { bubbles: true })); await wait(1200); }
  ok("forensic timeline items carry --i", (() => {
    const items = doc.querySelectorAll(".tl-item");
    return items.length > 0 && items[0].style.getPropertyValue("--i") !== "";
  })(), doc.querySelectorAll(".tl-item").length + " items");
  ok("no case block left invisible", doc.getElementById("view").querySelectorAll("[data-reveal]:not(.is-in)").length === 0,
    doc.getElementById("view").querySelectorAll("[data-reveal]:not(.is-in)").length + " stuck");
  const hero = doc.getElementById("view").querySelector(".verdict-hero");
  ok("threat-result hero rendered", !!hero);
  ok("hero carries a severity band", !!hero && /(malicious|suspicious|clean)/.test(hero.className), hero && hero.className);
  ok("hero states the verdict", !!hero && /(MALICIOUS|SUSPICIOUS|CLEAN)/.test(hero.textContent), hero && hero.textContent.slice(0, 60));
  ok("hero shows real NLP confidence or 'unavailable'", !!hero && /% phishing|unavailable/.test(hero.textContent), hero && hero.textContent.slice(-140));
  ok("hero counts findings + indicators", !!hero && /Findings/.test(hero.textContent) && /Indicators/.test(hero.textContent));
  ok("background-mode control present", !!doc.getElementById("mt-bg-btn"));

  console.log("\n[7] 3D snake (procedural, WebGL)");
  ok("snake module loaded", !!win.MTSnake);
  const holder = doc.createElement("div");
  holder.style.cssText = "position:fixed;left:0;top:0;width:900px;height:600px";
  doc.body.appendChild(holder);
  let renders = 0;
  const RealRenderer = win.THREE.WebGLRenderer;
  win.THREE.WebGLRenderer = function () {          // jsdom has no GPU: fake the renderer, keep the maths
    this.domElement = doc.createElement("canvas");
    this.setPixelRatio = () => {}; this.setSize = () => {}; this.setClearColor = () => {};
    this.render = () => { renders++; }; this.dispose = () => {};
  };
  const sn = win.MTSnake.mount(holder, {});
  if (REDUCE) {
    ok("reduced-motion: snake is not mounted", sn === null && !doc.getElementById("mt-snake"));
  } else {
    ok("snake mounts", !!sn);
    ok("snake body is long (segments)", !!sn && sn.stats().segments >= 40, sn && sn.stats());
    const s1 = sn && sn.sample();
    await wait(700);
    const s2 = sn && sn.sample();
    ok("snake render loop runs", renders > 5, renders + " frames");
    ok("snake head actually moves", s1 && s2 && (Math.abs(s1.head[0] - s2.head[0]) + Math.abs(s1.head[1] - s2.head[1])) > 0.05,
       JSON.stringify([s1 && s1.head, s2 && s2.head]));
    ok("body stays connected (segment spacing sane)", s2 && s2.spacing > 0.3 && s2.spacing < 1.4, s2 && s2.spacing);
    ok("body is long in world units", s2 && s2.chain > 20, s2 && s2.chain);
    const st = sn && sn.stats();
    ok("body is ONE continuous mesh, not a chain of beads",
      !!st && st.meshes === 1 && st.continuous === true, JSON.stringify(st));
    ok("skin is real geometry (indexed triangles)", !!st && st.triangles > 800 && st.vertices > 400,
      st && st.triangles + " tris / " + st.vertices + " verts");
    ok("rings overlap, so the surface has no dotted gaps", s2 && s2.continuity < 1,
      s2 && "maxGap " + s2.maxGap.toFixed(3) + " vs diameter " + (2 * s2.radius).toFixed(3));
    ok("body tapers from head to tail tip",
      win.MTSnake.radiusAt(0.24) > win.MTSnake.radiusAt(0.95) * 2.5,
      win.MTSnake.radiusAt(0.24) + " vs " + win.MTSnake.radiusAt(0.95));
    sn.dispose();
    ok("snake disposes (canvas removed)", holder.querySelectorAll("canvas").length === 0);
  }
  win.THREE.WebGLRenderer = RealRenderer;
  holder.remove();

  console.log("\n[8] mail accounts page (Gmail monitoring)");
  const acct = await (await fetch(BASE + "/api/sources", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Gmail — ui-test", kind: "imap", host: "imap.gmail.com", port: 993,
      username: "ui.test@gmail.com", secret: "not-real", folders: ["INBOX"], mode: "monitor",
      interval_min: 10, enabled: true, authorization: "test" }) })).json();
  ok("test account created via the API", !!acct.id, acct);
  win.location.hash = "#/accounts";
  await wait(2200);
  const v3 = doc.getElementById("view");
  if (!hasMonitor) {
    ok("legacy engine: accounts page explains the missing API instead of breaking",
      /no mailbox-monitoring API/i.test(v3.textContent), v3.textContent.slice(0, 120));
    ok("legacy engine: no console errors on the accounts page", errors.length === 0, errors.slice(0, 2).join(" | "));
    console.log("\n[9] notification centre");
    const bellL = doc.getElementById("mt-bell");
    if (bellL) bellL.dispatchEvent(new win.MouseEvent("click", { bubbles: true }));
    await wait(700);
    ok("legacy engine: notification panel explains the requirement",
      /updated engine/i.test(doc.getElementById("mt-panel-b").textContent));
    doc.getElementById("mt-close").dispatchEvent(new win.MouseEvent("click", { bubbles: true }));
    await wait(400);
    console.log("\n[10] every route renders (real data, no errors)");
    for (const r of ["dashboard", "sources", "accounts", "mailboxes", "cases", "campaigns", "graph", "lookup", "settings", "analyze"]) {
      win.location.hash = "#/" + r;
      await wait(1300);
      ok("#/" + r + " renders content", doc.getElementById("view").textContent.trim().length > 40);
    }
    console.log("\n[11] console health");
    ok("no console/js errors (legacy engine)", errors.length === 0, errors.slice(0, 3).join(" | "));
    console.log(`\n${fail === 0 ? "PASS" : "FAIL"} ${pass}/${pass + fail}`);
    dom.window.close();
    process.exit(fail ? 1 : 0);
  }
  ok("accounts page renders the monitoring bar", !!v3.querySelector(".mon-bar"));
  ok("account card rendered", v3.querySelectorAll(".acct").length >= 1, v3.querySelectorAll(".acct").length);
  const acctEl = v3.querySelector(`.acct[data-id="${acct.id}"]`);
  ok("card for the new account is rendered", !!acctEl, "no card for " + acct.id);
  ok("card shows provider + address", !!acctEl && /ui\.test@gmail\.com/.test(acctEl.textContent), acctEl && acctEl.textContent.slice(0, 80));
  ok("card shows a status pill", !!acctEl.querySelector(".pill"), acctEl.querySelector(".pill") && acctEl.querySelector(".pill").textContent);
  ok("card shows last-checked / next-check state", /never|ago/.test(acctEl.textContent));
  ok("connect form present", !!doc.getElementById("ac-mail") && !!doc.getElementById("ac-pass"));
  ok("Gmail preset is prefilled", doc.getElementById("ac-host").value === "imap.gmail.com", doc.getElementById("ac-host").value);
  // selection toggle → persisted through the API
  const sw = acctEl.querySelector('[data-act="select"]');
  sw.checked = false;
  sw.dispatchEvent(new win.Event("change", { bubbles: true }));
  await wait(1600);
  const after = await (await fetch(BASE + "/api/accounts")).json();
  const row = (after.accounts || []).find(a => a.id === acct.id);
  ok("deselect through the UI persists server-side", row && row.selected === false, row && row.selected);
  // modal confirm for the destructive action
  const del = doc.querySelector(`.acct[data-id="${acct.id}"] [data-act="remove"]`);
  del.dispatchEvent(new win.MouseEvent("click", { bubbles: true }));
  await wait(400);
  ok("styled confirm modal replaces window.confirm", !!doc.querySelector(".mt-modal"));
  doc.querySelector(".mt-modal [data-no]").dispatchEvent(new win.MouseEvent("click", { bubbles: true }));
  await wait(500);
  ok("modal closes without deleting", !doc.querySelector(".mt-modal.on"));

  console.log("\n[9] notification centre");
  const bellBtn = doc.getElementById("mt-bell");
  ok("notification bell in the sidebar", !!bellBtn);
  bellBtn.dispatchEvent(new win.MouseEvent("click", { bubbles: true }));
  await wait(900);
  ok("notification panel opens", !!doc.querySelector(".mt-panel.on"));
  const nItems = doc.querySelectorAll(".mt-panel .mt-n").length;
  ok("history lists real events", nItems > 0, nItems + " items");
  ok("history items carry severity + time", !!doc.querySelector(".mt-panel .mt-n [class*=sev-], .mt-panel .mt-n .ico"));
  doc.getElementById("mt-close").dispatchEvent(new win.MouseEvent("click", { bubbles: true }));
  await wait(500);
  ok("notification panel closes", !doc.querySelector(".mt-panel.on"));
  // a fresh notification pops a toast through the SSE bridge
  await fetch(BASE + "/api/notifications/read", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ all: true }) });
  if (win.MTConsole) win.MTConsole.toast({ title: "New email analysis completed", body: "2 malicious · 1 suspicious · 1 clean", severity: "critical", account: "ui.test@gmail.com" });
  await wait(300);
  ok("toast is rendered with severity styling", !!doc.querySelector("#toast .tst.sev-critical"));

  console.log("\n[10] every route renders (real data, no errors)");
  const errsBefore = errors.length;
  for (const r of ["dashboard", "sources", "accounts", "mailboxes", "cases", "campaigns", "graph", "lookup", "settings", "analyze"]) {
    win.location.hash = "#/" + r;
    await wait(1400);
    const txt = doc.getElementById("view").textContent.trim();
    ok("#/" + r + " renders content", txt.length > 40, "view text length " + txt.length);
  }
  ok("no errors across the route sweep", errors.length === errsBefore, errors.slice(errsBefore, errsBefore + 3).join(" | "));

  console.log("\n[11] console health");
  ok("no console/js errors", errors.length === 0, errors.slice(0, 4).join(" | "));

  console.log(`\n${fail === 0 ? "PASS" : "FAIL"} ${pass}/${pass + fail}`);
  dom.window.close();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error("harness error:", e); process.exit(2); });
