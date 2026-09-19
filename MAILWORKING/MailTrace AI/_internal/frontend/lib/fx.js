/* MailTrace AI — motion, ambient background and performance utilities.
   Plain script (no bundler, no modules) so it also works from file:// inside the desktop shell. */
(function () {
  "use strict";
  var w = window;

  /* ---------------------------------------------------------- capability / quality tier ---- */
  var reduceMotion = w.matchMedia && w.matchMedia("(prefers-reduced-motion: reduce)").matches;
  function tier() {
    var mem = navigator.deviceMemory || 4;                     // Chrome only; sane default otherwise
    var cores = navigator.hardwareConcurrency || 4;
    var small = Math.min(w.innerWidth, w.innerHeight) < 620;
    if (reduceMotion) return "low";
    if (mem <= 2 || cores <= 2 || small) return "low";
    if (mem <= 4 || cores <= 4) return "mid";
    return "high";
  }
  var QUALITY = tier();
  var gl_ok = (function () {
    try {
      var c = document.createElement("canvas");
      return !!(w.WebGLRenderingContext && (c.getContext("webgl") || c.getContext("experimental-webgl")));
    } catch (e) { return false; }
  })();

  /* --------------------------------------------------------------- ambient background ---- */
  var bg = { canvas: null, ctx: null, raf: 0, dots: [], grid: 0, t: 0, w: 0, h: 0, running: false };
  function bgInit() {
    if (bg.canvas || QUALITY === "low") return;
    var c = document.createElement("canvas");
    c.className = "mt-bg-canvas";
    document.body.insertBefore(c, document.body.firstChild);
    bg.canvas = c; bg.ctx = c.getContext("2d");
    bgResize();
    w.addEventListener("resize", bgResize, { passive: true });
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) bgStop(); else bgStart();
    });
    bgStart();
  }
  function bgResize() {
    if (!bg.canvas) return;
    var dpr = Math.min(w.devicePixelRatio || 1, 1.75);
    bg.w = w.innerWidth; bg.h = w.innerHeight;
    bg.canvas.width = bg.w * dpr; bg.canvas.height = bg.h * dpr;
    bg.canvas.style.width = bg.w + "px"; bg.canvas.style.height = bg.h + "px";
    bg.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    var n = QUALITY === "high" ? 90 : 50;
    bg.dots = [];
    for (var i = 0; i < n; i++) bg.dots.push({
      x: Math.random() * bg.w, y: Math.random() * bg.h,
      r: Math.random() * 1.5 + 0.35, s: Math.random() * 0.16 + 0.02,
      a: Math.random() * 0.4 + 0.08, p: Math.random() * 6.28
    });
  }
  function bgFrame() {
    if (!bg.ctx) return;
    var g = bg.ctx, t = (bg.t += 0.006);
    g.clearRect(0, 0, bg.w, bg.h);
    // drifting particulate: depth without weight
    for (var i = 0; i < bg.dots.length; i++) {
      var d = bg.dots[i];
      d.y -= d.s; if (d.y < -4) { d.y = bg.h + 4; d.x = Math.random() * bg.w; }
      var a = d.a * (0.55 + 0.45 * Math.sin(t * 2 + d.p));
      g.beginPath(); g.arc(d.x + Math.sin(t + d.p) * 8, d.y, d.r, 0, 6.2832);
      g.fillStyle = "rgba(112,214,214," + a.toFixed(3) + ")"; g.fill();
    }
    bg.raf = requestAnimationFrame(bgFrame);
  }
  function bgStart() { if (bg.canvas && !bg.running) { bg.running = true; bg.raf = requestAnimationFrame(bgFrame); } }
  function bgStop() { if (bg.raf) cancelAnimationFrame(bg.raf); bg.raf = 0; bg.running = false; }

  /* ------------------------------------------------------------------ reveal on scroll ---- */
  var io = null;
  function reveal(scope) {
    var els = (scope || document).querySelectorAll("[data-reveal]:not(.is-in)");
    if (!("IntersectionObserver" in w)) {
      for (var i = 0; i < els.length; i++) els[i].classList.add("is-in");
      return;
    }
    if (!io) io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("is-in"); io.unobserve(e.target); }
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.06 });
    for (var j = 0; j < els.length; j++) io.observe(els[j]);
  }

  /* -------------------------------------------------------------- animated number count ---- */
  function countTo(el, to, opts) {
    opts = opts || {};
    var dur = reduceMotion ? 0 : (opts.duration || 900);
    var dec = opts.decimals || 0, from = parseFloat(el.getAttribute("data-v") || el.textContent.replace(/[^0-9.\-]/g, "")) || 0;
    el.setAttribute("data-v", to);
    if (!dur) { el.textContent = fmt(to, dec, opts.suffix); return; }
    var t0 = performance.now();
    function step(now) {
      var p = Math.min(1, (now - t0) / dur);
      var e = 1 - Math.pow(1 - p, 3);
      el.textContent = fmt(from + (to - from) * e, dec, opts.suffix);
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }
  function fmt(v, dec, suffix) {
    var s = dec ? v.toFixed(dec) : Math.round(v).toLocaleString("en-US");
    return s + (suffix || "");
  }

  /* --------------------------------------------------------------- subtle tilt / parallax ---- */
  function tilt(el, strength) {
    if (QUALITY === "low" || reduceMotion) return function () {};
    var s = strength || 6, rx = 0, ry = 0, tx = 0, ty = 0, raf = 0;
    function loop() {
      rx += (tx - rx) * 0.09; ry += (ty - ry) * 0.09;
      el.style.transform = "perspective(1000px) rotateX(" + rx.toFixed(2) + "deg) rotateY(" + ry.toFixed(2) + "deg)";
      if (Math.abs(tx - rx) > 0.01 || Math.abs(ty - ry) > 0.01) raf = requestAnimationFrame(loop); else raf = 0;
    }
    function move(e) {
      var r = el.getBoundingClientRect();
      tx = ((e.clientY - r.top) / r.height - 0.5) * -s;
      ty = ((e.clientX - r.left) / r.width - 0.5) * s;
      if (!raf) raf = requestAnimationFrame(loop);
    }
    function leave() { tx = 0; ty = 0; if (!raf) raf = requestAnimationFrame(loop); }
    el.addEventListener("pointermove", move);
    el.addEventListener("pointerleave", leave);
    return function () { el.removeEventListener("pointermove", move); el.removeEventListener("pointerleave", leave); if (raf) cancelAnimationFrame(raf); el.style.transform = ""; };
  }

  /* ------------------------------------------------------------- view transition helper ---- */
  function enter(el) {
    el.classList.add("mt-enter");
    requestAnimationFrame(function () { requestAnimationFrame(function () { el.classList.add("mt-enter-in"); }); });
  }

  /* ------------------------------------------------------------------ visibility gating ---- */
  function whenVisible(el, on, off) {
    if (!("IntersectionObserver" in w)) { on(); return function () {}; }
    var vis = false;
    var ob = new IntersectionObserver(function (e) {
      var now = e[0].isIntersecting && !document.hidden;
      if (now === vis) return;
      vis = now; now ? on() : off();
    }, { threshold: 0.02 });
    ob.observe(el);
    var vc = function () { var now = vis && !document.hidden; if (!now && vis) { vis = false; off(); } else if (!vis && !document.hidden && el.getBoundingClientRect().top < innerHeight) { vis = true; on(); } };
    document.addEventListener("visibilitychange", vc);
    return function () { ob.disconnect(); document.removeEventListener("visibilitychange", vc); };
  }

  w.MTfx = {
    quality: QUALITY, reduceMotion: reduceMotion, webgl: gl_ok,
    bg: bgInit, reveal: reveal, count: countTo, tilt: tilt, enter: enter, whenVisible: whenVisible,
    fmt: fmt
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bgInit); else bgInit();
})();
