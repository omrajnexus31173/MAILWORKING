/* MailTrace AI — motion layer (pass 2).
   Pure animation/interaction glue: no data, no analysis logic, no network calls.
   Everything degrades to a static UI when prefers-reduced-motion is set or when the
   capability tier reported by lib/fx.js is "low". */
(function () {
  "use strict";
  var w = window, doc = document;
  var fx = w.MTfx || {};
  var reduce = !!fx.reduceMotion;
  var Q = fx.quality || "mid";
  var OFF = reduce || Q === "low";
  var noop = function () {};

  /* ------------------------------------------------------------------ ambient depth orbs ------------ */
  var orbDone = false;
  function orbs() {
    if (orbDone || OFF) return;
    orbDone = true;
    var a = doc.createElement("div"); a.className = "mt-orb a";
    var b = doc.createElement("div"); b.className = "mt-orb b";
    doc.body.insertBefore(b, doc.body.firstChild);
    doc.body.insertBefore(a, doc.body.firstChild);
  }

  /* ------------------------------------------------------------------ boot / splash ----------------- */
  var boot = { el: null, t0: (w.performance && performance.now) ? performance.now() : Date.now(), ended: false };
  boot.label = function (txt) {
    var t = doc.getElementById("boot-t"); if (t && txt) t.textContent = txt;
  };
  boot.end = function (txt) {
    if (boot.ended) return;
    boot.ended = true;
    var el = doc.getElementById("boot"); if (!el) return;
    boot.label(txt || "ready");
    var wait = Math.max(0, 620 - ((w.performance && performance.now ? performance.now() : Date.now()) - boot.t0));
    setTimeout(function () { el.classList.add("gone"); setTimeout(function () { el.remove(); }, 700); }, wait);
  };

  /* ------------------------------------------------------------------ route transition -------------- */
  var wipeEl = null, wipeTimer = 0;
  function route() {
    if (OFF) return noop;
    if (!wipeEl) {
      wipeEl = doc.createElement("div");
      wipeEl.className = "mt-wipe";
      wipeEl.appendChild(doc.createElement("i"));
      doc.body.appendChild(wipeEl);
    }
    wipeEl.classList.remove("go", "out");
    void wipeEl.offsetWidth;
    wipeEl.classList.add("go");
    clearTimeout(wipeTimer);
    wipeTimer = setTimeout(function () { wipeEl.classList.add("out"); }, 240);
    return function () {
      clearTimeout(wipeTimer);
      wipeTimer = setTimeout(function () {
        if (wipeEl) { wipeEl.classList.add("out"); setTimeout(function () { if (wipeEl) wipeEl.classList.remove("go", "out"); }, 520); }
      }, 120);
    };
  }

  /* ------------------------------------------------------------------ text decode (real text only) -- */
  var GLYPHS = "▚▞░▒▓/\\<>*#%@$&+=-_";
  function scramble(el, dur) {
    if (!el) return;
    var final = el.getAttribute("data-txt");
    if (final == null) { final = el.textContent; el.setAttribute("data-txt", final); }
    if (OFF) { el.textContent = final; return; }
    var t0 = performance.now(), n = final.length, d = dur || 480;
    (function step(now) {
      var p = Math.min(1, (now - t0) / d), rev = Math.floor(p * n), out = "";
      for (var i = 0; i < n; i++) {
        var ch = final.charAt(i);
        out += (i < rev || ch === " ") ? ch : GLYPHS.charAt((Math.random() * GLYPHS.length) | 0);
      }
      el.textContent = out;
      if (p < 1) requestAnimationFrame(step); else el.textContent = final;
    })(t0);
  }

  /* ------------------------------------------------------------------ micro-interaction binding ----- */
  var bound = false;
  function bind() {
    if (bound) return;
    bound = true;
    doc.addEventListener("pointerdown", function (e) {
      if (OFF) return;
      var b = e.target && e.target.closest ? e.target.closest(".btn, .tag, nav a, .sample, .mbcard, .threat-row") : null;
      if (!b || b.disabled) return;
      var r = b.getBoundingClientRect(), d = Math.max(r.width, r.height) * 2.3;
      var s = doc.createElement("span");
      s.className = "rip";
      s.style.width = s.style.height = d + "px";
      s.style.left = (e.clientX - r.left - d / 2) + "px";
      s.style.top = (e.clientY - r.top - d / 2) + "px";
      b.appendChild(s);
      setTimeout(function () { s.remove(); }, 700);
    }, { passive: true });

    var last = 0, curLit = null;
    doc.addEventListener("pointermove", function (e) {
      var now = performance.now();
      if (now - last < 16) return;
      last = now;
      var t = e.target;
      var card = t && t.closest ? t.closest(".card, .drop, .mbcard, .sample, .threat-row") : null;
      if (card !== curLit) {
        if (curLit) curLit.classList.remove("lit");
        curLit = card;
        if (card) card.classList.add("lit");
      }
      if (card && !OFF) {
        var r = card.getBoundingClientRect();
        card.style.setProperty("--mx", (((e.clientX - r.left) / r.width) * 100).toFixed(1) + "%");
        card.style.setProperty("--my", (((e.clientY - r.top) / r.height) * 100).toFixed(1) + "%");
      }
      if (!OFF && Q === "high") {                       // magnetic pull on primary buttons only
        var b = t && t.closest ? t.closest(".btn.p") : null;
        if (b) {
          var rb = b.getBoundingClientRect();
          b.style.transform = "translate(" + (((e.clientX - (rb.left + rb.width / 2)) / rb.width) * 7).toFixed(2) + "px," +
            (((e.clientY - (rb.top + rb.height / 2)) / rb.height) * 4.5).toFixed(2) + "px)";
        }
      }
    }, { passive: true });

    doc.addEventListener("pointerout", function (e) {
      var b = e.target && e.target.closest ? e.target.closest(".btn.p") : null;
      if (b) b.style.transform = "";
      if (e.relatedTarget == null && curLit) { curLit.classList.remove("lit"); curLit = null; }
    }, { passive: true });
  }

  /* ------------------------------------------------------------------ AI processing visual ---------- */
  /* Draws a live neural/scan texture while the backend is actually working, then visibly stops.
     It never reports progress: the pipeline nodes carry that information. */
  function aiScan(container) {
    if (!container) return { done: noop, fail: noop, dispose: noop };
    var wrap = doc.createElement("div");
    wrap.className = "ai-scan";
    var cv = doc.createElement("canvas");
    wrap.appendChild(cv);
    container.appendChild(wrap);
    var ctx = cv.getContext ? cv.getContext("2d") : null;
    if (!ctx || OFF) {
      wrap.remove();
      return { done: noop, fail: noop, dispose: noop };
    }
    var dpr = Math.min(w.devicePixelRatio || 1, 1.75);
    var W = 0, H = 0, nodes = [], links = [], raf = 0, t = 0, state = "run", dead = false;
    function size() {
      W = container.clientWidth || 600;
      H = container.clientHeight || 200;
      cv.width = Math.max(1, W * dpr); cv.height = Math.max(1, H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      var n = Q === "high" ? 30 : 18, i, j;
      nodes = [];
      for (i = 0; i < n; i++) nodes.push({
        x: Math.random() * W, y: Math.random() * H,
        vx: (Math.random() - .5) * .22, vy: (Math.random() - .5) * .22,
        r: Math.random() * 1.5 + .8, hot: Math.random() < .28, ph: Math.random() * 6.28
      });
      links = [];
      var lim = Math.min(W, H) * .34;
      for (i = 0; i < n; i++) for (j = i + 1; j < n; j++) {
        var a = nodes[i], b = nodes[j];
        if (Math.hypot(a.x - b.x, a.y - b.y) < lim) links.push({ a: a, b: b, p: Math.random(), s: .004 + Math.random() * .008 });
      }
    }
    function frame() {
      if (dead) return;
      t += .012;
      ctx.clearRect(0, 0, W, H);
      var i, l;
      for (i = 0; i < links.length; i++) {
        l = links[i];
        var dx = l.b.x - l.a.x, dy = l.b.y - l.a.y;
        ctx.strokeStyle = "rgba(89,168,255,.14)";
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(l.a.x, l.a.y); ctx.lineTo(l.b.x, l.b.y); ctx.stroke();
        l.p += l.s; if (l.p > 1) l.p -= 1;
        ctx.fillStyle = "rgba(77,227,212,.75)";
        ctx.beginPath(); ctx.arc(l.a.x + dx * l.p, l.a.y + dy * l.p, 1.35, 0, 6.283); ctx.fill();
      }
      for (i = 0; i < nodes.length; i++) {
        var nd = nodes[i];
        nd.x += nd.vx; nd.y += nd.vy;
        if (nd.x < 0 || nd.x > W) nd.vx *= -1;
        if (nd.y < 0 || nd.y > H) nd.vy *= -1;
        var pulse = .55 + .45 * Math.sin(t * 3 + nd.ph);
        ctx.fillStyle = nd.hot ? "rgba(255,180,84," + (.35 + pulse * .5).toFixed(3) + ")" : "rgba(125,200,255," + (.25 + pulse * .45).toFixed(3) + ")";
        ctx.beginPath(); ctx.arc(nd.x, nd.y, nd.r * (1 + pulse * .4), 0, 6.283); ctx.fill();
      }
      // rotating scan rings
      var cx = W - 62, cy = 56, rr = 26;
      for (var k = 0; k < 3; k++) {
        ctx.strokeStyle = "rgba(77,227,212," + (.30 - k * .08).toFixed(3) + ")";
        ctx.lineWidth = 1.2;
        ctx.beginPath(); ctx.arc(cx, cy, rr + k * 11, t * (1.6 - k * .35), t * (1.6 - k * .35) + 3.4); ctx.stroke();
      }
      if (state === "run") raf = requestAnimationFrame(frame);
    }
    function finish(ok) {
      if (state !== "run") return;
      state = ok ? "done" : "fail";
      var t0 = performance.now();
      (function burst(now) {
        var p = Math.min(1, (now - t0) / 520);
        ctx.clearRect(0, 0, W, H);
        var cx = W - 62, cy = 56;
        ctx.strokeStyle = ok ? "rgba(61,220,151," + (1 - p).toFixed(3) + ")" : "rgba(255,95,109," + (1 - p).toFixed(3) + ")";
        ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(cx, cy, 12 + p * 74, 0, 6.283); ctx.stroke();
        if (p < 1) requestAnimationFrame(burst);
        else { cv.classList.add("fin"); setTimeout(dispose, 650); }
      })(t0);
    }
    function dispose() {
      dead = true;
      if (raf) cancelAnimationFrame(raf);
      raf = 0;
      if (onResize) { w.removeEventListener("resize", onResize); onResize = null; }
      wrap.remove();
    }
    var onResize = function () { size(); };
    w.addEventListener("resize", onResize);
    size();
    raf = requestAnimationFrame(frame);
    return { done: function () { finish(true); }, fail: function () { finish(false); }, dispose: dispose };
  }

  /* ------------------------------------------------------------------ skeletons --------------------- */
  function skeleton(rows) {
    var n = rows || 3, out = "";
    for (var i = 0; i < n; i++) out += '<div class="skel ' + (i % 3 === 0 ? "w88" : i % 3 === 1 ? "w70" : "w45") + '"></div>';
    return out;
  }

  /* ------------------------------------------------------------------ per-view automation ----------- */
  function auto(root) {
    var scope = root || doc;
    var view = doc.getElementById("view");
    var host = (scope === doc || !scope.querySelector) ? view : scope;
    if (!host) return;

    // 1. mark the major blocks so they animate in on scroll (never leaves content invisible)
    var sel = "#view > .card, #view > .grid, #view > .hero, #view > .page-head, #view > .mbbar, #view > .tl, .grid > .card, .grid > div > .card";
    var blocks = host.querySelectorAll ? host.querySelectorAll(sel) : [];
    for (var i = 0; i < blocks.length; i++) {
      var el = blocks[i];
      if (el.hasAttribute("data-reveal")) continue;
      var p = el.parentElement;
      if (p && p.closest && p.closest("[data-reveal]")) continue;   // already inside a revealed block
      el.setAttribute("data-reveal", "");
    }
    // 2. cursor-spotlight layer + sequenced children
    var cards = host.querySelectorAll(".card, .drop, .mbcard, .sample");
    for (var j = 0; j < cards.length; j++) {
      var hasSpot = false, kids0 = cards[j].children;
      for (var q = 0; q < kids0.length; q++) if (kids0[q].className === "spot") { hasSpot = true; break; }
      if (!hasSpot) {
        var sp = doc.createElement("i");
        sp.className = "spot";
        cards[j].insertBefore(sp, cards[j].firstChild);
      }
    }
    var seqs = host.querySelectorAll(".mt-seq");
    for (var s = 0; s < seqs.length; s++) {
      var kids = seqs[s].children;
      for (var k = 0; k < kids.length; k++) kids[k].style.setProperty("--i", k);
    }
    // 3. stagger delays for revealed siblings
    var rev = host.querySelectorAll("[data-reveal]"), counts = {};
    for (var r = 0; r < rev.length; r++) {
      var node = rev[r], par = node.parentElement;
      if (!par) continue;
      if (!par.__mtSeq) par.__mtSeq = 0;
      var n = par.__mtSeq++;
      node.style.setProperty("--d", Math.min(5, n) * 55 + "ms");
    }
    // 4. headline decode (real text only)
    if (!OFF) {
      var h = host.querySelector(".page-head h1");
      if (h) scramble(h, 460);
      var eb = host.querySelector(".page-head .eyebrow");
      if (eb) scramble(eb, 320);
    }
    // 5. parallax targets
    parCollect(host);
  }

  /* ------------------------------------------------------------------ scroll parallax --------------- */
  var parItems = [], parRaf = 0, parBound = false;
  function parCollect(host) {
    if (OFF) return;
    var els = host.querySelectorAll("[data-par]");
    for (var i = 0; i < els.length; i++) if (parItems.indexOf(els[i]) < 0) parItems.push(els[i]);
    if (!parBound) {
      parBound = true;
      w.addEventListener("scroll", parTick, { passive: true });
      w.addEventListener("resize", parTick, { passive: true });
    }
    parTick();
  }
  function parTick() {
    if (parRaf || !parItems.length) return;
    parRaf = requestAnimationFrame(function () {
      parRaf = 0;
      var vh = w.innerHeight;
      for (var i = parItems.length - 1; i >= 0; i--) {
        var el = parItems[i];
        if (!el.isConnected) { parItems.splice(i, 1); continue; }
        var r = el.getBoundingClientRect();
        if (r.bottom < -240 || r.top > vh + 240) continue;
        var depth = parseFloat(el.getAttribute("data-par")) || 12;
        var p = (r.top + r.height / 2 - vh / 2) / vh;
        el.style.setProperty("--py", (-p * depth).toFixed(2) + "px");
      }
    });
  }

  /* ------------------------------------------------------------------ reveal (wraps MTfx.reveal) --- */
  var origReveal = fx.reveal;
  function reveal(scope) {                    // coalesced: views mutate repeatedly while graphs render
    pending = scope || doc;
    if (revTimer) return;
    revTimer = setTimeout(function () { revTimer = 0; revealNow(pending); }, 60);
  }
  var revTimer = 0, pending = null;
  function revealNow(scope) {
    auto(scope);
    if (origReveal) origReveal(scope);
    else {
      var els = (scope || doc).querySelectorAll("[data-reveal]");
      for (var i = 0; i < els.length; i++) els[i].classList.add("is-in");
    }
    // safety net: nothing may stay invisible if the observer never fires (hidden tab, tiny viewport…)
    var host = scope || doc;
    setTimeout(function () {
      var left = host.querySelectorAll("[data-reveal]:not(.is-in)");
      for (var k = 0; k < left.length; k++) {
        var el = left[k];
        if (!el.offsetParent) { el.classList.add("is-in"); continue; }
        var r = el.getBoundingClientRect();
        if (r.top < w.innerHeight && r.bottom > 0) el.classList.add("is-in");
      }
    }, 900);
  }
  w.MTfx.reveal = reveal;

  /* ------------------------------------------------------------------ count-up flash ---------------- */
  var origCount = fx.count;
  w.MTfx.count = function (el, to, opts) {
    if (el) { el.classList.remove("mt-flash"); void el.offsetWidth; el.classList.add("mt-flash"); }
    return origCount ? origCount(el, to, opts) : undefined;
  };

  /* ------------------------------------------------------------------ export ----------------------- */
  w.MTmotion = {
    boot: boot, route: route, aiScan: aiScan, skeleton: skeleton, scramble: scramble,
    bind: bind, reveal: reveal, orbs: orbs, off: OFF, quality: Q
  };

  function start() {
    orbs();
    bind();
    if (fx.bg) fx.bg();
    setTimeout(function () { boot.end(); }, 4200);   // hard cap: the UI must never stay blocked
  }
  if (doc.readyState === "loading") doc.addEventListener("DOMContentLoaded", start); else start();
})();
