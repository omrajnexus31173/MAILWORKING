/* MailTrace AI — interactive 3D global threat globe (Three.js r97, vendored).
   Renders ONLY real coordinates: points whose location resolved to city/region/country coordinates
   are drawn as solid nodes; records that only have a country (no coordinates) are drawn as hollow,
   clearly-labelled approximate markers using that country's centroid — never as precise pins. */
(function () {
  "use strict";
  var T = window.THREE;
  var V3 = T.Vector3;

  function llVec(lat, lon, r) {
    var phi = (90 - lat) * Math.PI / 180, th = (lon + 180) * Math.PI / 180;
    return new V3(-r * Math.sin(phi) * Math.cos(th), r * Math.cos(phi), r * Math.sin(phi) * Math.sin(th));
  }
  function sevColor(score) {
    if (score == null) return 0x59a8ff;
    return score >= 80 ? 0xff5f6d : score >= 60 ? 0xff9f43 : score >= 35 ? 0xffd166 : score >= 15 ? 0x59a8ff : 0x3ddc97;
  }
  function clamp(v, a, b) { return v < a ? a : v > b ? b : v; }
  /* three renamed addAttribute → setAttribute in r110; this build ships r97 (offline-safe) */
  function setAttr(geo, name, attr) {
    if (geo.setAttribute) geo.setAttribute(name, attr); else geo.addAttribute(name, attr);
    return geo;
  }

  /* lat/lon → the group rotation that brings that point to face the camera */
  function faceRotation(lat, lon) {
    var th = (lon + 180) * Math.PI / 180;
    return { x: lat * Math.PI / 180, y: Math.atan2(Math.cos(th), Math.sin(th)) };
  }

  function create(container, opts) {
    opts = opts || {};
    if (!T) return { unsupported: true, dispose: function () {} };
    var low = (window.MTfx && window.MTfx.quality === "low") || (window.MTfx && window.MTfx.reduceMotion);
    var W = container.clientWidth || 600, H = container.clientHeight || 420;

    var scene = new T.Scene();
    var camera = new T.PerspectiveCamera(36, W / H, 0.1, 100);
    camera.position.set(0, 0, 3.15);
    var renderer = new T.WebGLRenderer({ antialias: !low, alpha: true, powerPreference: "high-performance" });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, low ? 1 : 1.75));
    renderer.setSize(W, H);
    renderer.setClearColor(0x000000, 0);
    container.appendChild(renderer.domElement);
    renderer.domElement.className = "globe-canvas";

    var root = new T.Group();          // holds everything, receives user rotation
    scene.add(root);
    var globe = new T.Group();         // ocean + land + graticule + markers
    root.add(globe);

    var disposables = [];
    function track(o) { disposables.push(o); return o; }

    /* ------------------------------------------------------------------ ocean sphere ---- */
    var oceanMat = track(new T.ShaderMaterial({
      uniforms: { uTime: { value: 0 }, uBase: { value: new T.Color(0x0a1526) }, uRim: { value: new T.Color(0x2ad6c8) } },
      vertexShader:
        "varying vec3 vN; varying vec3 vP; varying vec3 vV;" +
        "void main(){ vN = normalize(normalMatrix * normal); vP = position;" +
        " vec4 mv = modelViewMatrix * vec4(position,1.0); vV = -mv.xyz;" +
        " gl_Position = projectionMatrix * mv; }",
      fragmentShader:
        "uniform vec3 uBase; uniform vec3 uRim; uniform float uTime; varying vec3 vN; varying vec3 vP; varying vec3 vV;" +
        "void main(){ float f = pow(1.0 - clamp(dot(normalize(vN), normalize(vV)),0.0,1.0), 2.4);" +
        " float lam = clamp(dot(normalize(vN), normalize(vec3(0.55,0.75,0.9))),0.0,1.0);" +
        " vec3 c = uBase * (0.45 + 0.75*lam) + uRim * f * 0.55;" +
        " float band = exp(-pow((vP.y - sin(uTime*0.22)*0.95) * 7.0, 2.0));" +
        " c += uRim * band * 0.09;" +
        " gl_FragColor = vec4(c, 1.0); }",
      transparent: false
    }));
    var oceanGeo = track(new T.SphereBufferGeometry(0.995, low ? 40 : 64, low ? 28 : 48));
    globe.add(new T.Mesh(oceanGeo, oceanMat));

    /* ------------------------------------------------------------------- atmosphere ---- */
    if (!low) {
      var atmoMat = track(new T.ShaderMaterial({
        uniforms: { uColor: { value: new T.Color(0x35c9e8) } },
        vertexShader: "varying vec3 vN; varying vec3 vV;" +
          "void main(){ vN = normalize(normalMatrix*normal); vec4 mv = modelViewMatrix*vec4(position,1.0); vV = -mv.xyz;" +
          " gl_Position = projectionMatrix*mv; }",
        fragmentShader: "uniform vec3 uColor; varying vec3 vN; varying vec3 vV;" +
          "void main(){ float f = pow(1.0 - clamp(dot(normalize(vN), normalize(vV)),0.0,1.0), 3.2);" +
          " gl_FragColor = vec4(uColor, f*0.55); }",
        side: T.BackSide, blending: T.AdditiveBlending, transparent: true, depthWrite: false
      }));
      var atmoGeo = track(new T.SphereBufferGeometry(1.19, 48, 32));
      root.add(new T.Mesh(atmoGeo, atmoMat));
    }

    /* -------------------------------------------------------- land outlines + borders ---- */
    function segments(packed, radius, color, opacity) {
      var c = packed.c, o = packed.o, arr = [];
      for (var k = 0; k < o.length; k += 2) {
        var a = o[k], b = o[k + 1];
        for (var i = a; i < b - 2; i += 2) {
          var p1 = llVec(c[i + 1], c[i], radius), p2 = llVec(c[i + 3], c[i + 2], radius);
          arr.push(p1.x, p1.y, p1.z, p2.x, p2.y, p2.z);
        }
      }
      var g = track(new T.BufferGeometry());
      setAttr(g, "position", new T.BufferAttribute(new Float32Array(arr), 3));
      var m = track(new T.LineBasicMaterial({ color: color, transparent: true, opacity: opacity }));
      return new T.LineSegments(g, m);
    }
    var world = window.MT_WORLD;
    if (world) {
      globe.add(segments(world.land, 1.0, 0x4fd8cf, 0.62));
      globe.add(segments(world.borders, 1.0015, 0x2f6f97, 0.45));
    }

    /* -------------------------------------------------------------------- graticule ---- */
    (function () {
      var arr = [], R = 1.002, i, j, step = 15;
      for (var lat = -75; lat <= 75; lat += step) {
        for (j = -180; j < 180; j += 3) {
          var a = llVec(lat, j, R), b = llVec(lat, j + 3, R);
          arr.push(a.x, a.y, a.z, b.x, b.y, b.z);
          if (lat === 0) break;                              // equator drawn once
        }
      }
      for (var lon = -180; lon < 180; lon += step) {
        for (i = -87; i < 87; i += 3) {
          var c = llVec(i, lon, R), d = llVec(i + 3, lon, R);
          arr.push(c.x, c.y, c.z, d.x, d.y, d.z);
        }
      }
      var g = track(new T.BufferGeometry());
      setAttr(g, "position", new T.BufferAttribute(new Float32Array(arr), 3));
      var m = track(new T.LineBasicMaterial({ color: 0x4f7fb5, transparent: true, opacity: 0.14 }));
      globe.add(new T.LineSegments(g, m));
    })();

    /* ---------------------------------------------------------------- particle field ---- */
    var dust = null;
    if (!low) {
      var n = 420, pos = new Float32Array(n * 3);
      for (var i = 0; i < n; i++) {
        var u = Math.random() * 2 - 1, a2 = Math.random() * Math.PI * 2, s = Math.sqrt(1 - u * u);
        var r = 1.25 + Math.random() * 0.9;
        pos[i * 3] = Math.cos(a2) * s * r; pos[i * 3 + 1] = u * r; pos[i * 3 + 2] = Math.sin(a2) * s * r;
      }
      var dg = track(new T.BufferGeometry());
      setAttr(dg, "position", new T.BufferAttribute(pos, 3));
      var dm = track(new T.PointsMaterial({ color: 0x8fd7ff, size: 0.012, transparent: true, opacity: 0.5, sizeAttenuation: true, depthWrite: false }));
      dust = new T.Points(dg, dm);
      root.add(dust);
    }

    /* --------------------------------------------------------------- markers and arcs ---- */
    var markerGroup = new T.Group(); globe.add(markerGroup);
    var arcGroup = new T.Group(); globe.add(arcGroup);
    var markers = [], arcs = [], pulses = [];
    var markerGeo = track(new T.SphereBufferGeometry(1, 10, 8));
    var ringGeo = track(new T.RingBufferGeometry(0.028, 0.038, 24));
    var beamGeo = track(new T.CylinderBufferGeometry(0.0035, 0.0035, 1, 5, 1, true));

    function clearGroup(g, list) {
      for (var i = 0; i < list.length; i++) {
        var o = list[i];
        if (o.mesh) g.remove(o.mesh);
        (o.mats || []).forEach(function (m) { m.dispose(); });
        if (o.geo) o.geo.dispose();
      }
      list.length = 0;
      pulses.length = 0;
    }

    function makeMarker(p) {
      var col = sevColor(p.score);
      var v = llVec(p.lat, p.lon, 1.004);
      var grp = new T.Group();
      grp.position.copy(v);
      grp.lookAt(new V3(0, 0, 0));
      // body
      var bodyMat = new T.MeshBasicMaterial({ color: col, transparent: true, opacity: p.approximate ? 0.5 : 0.95 });
      var body = new T.Mesh(markerGeo, bodyMat);
      var s = (p.approximate ? 0.010 : 0.0135) * (1 + Math.min(0.6, (p.count || 1) / 22));
      body.scale.setScalar(s);
      grp.add(body);
      // surface ring (pulse)
      var ringMat = new T.MeshBasicMaterial({ color: col, transparent: true, opacity: p.approximate ? 0.28 : 0.55, side: T.DoubleSide, depthWrite: false });
      var ring = new T.Mesh(ringGeo, ringMat);
      ring.rotation.x = Math.PI / 2;
      grp.add(ring);
      // vertical beam for higher-risk, precise locations
      var beam = null;
      if (!p.approximate && (p.score || 0) >= 35) {
        var beamMat = new T.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.35, depthWrite: false });
        beam = new T.Mesh(beamGeo, beamMat);
        var beamLen = 0.10 + Math.min(0.22, (p.score || 0) / 400);
        beam.scale.set(1, beamLen, 1);
        beam.position.set(0, 0, 0);
        beam.rotation.x = -Math.PI / 2;                        // local +Y → outward normal
        beam.translateY(0.5 * beamLen);
        grp.add(beam);
      }
      markerGroup.add(grp);
      var mats = [bodyMat, ringMat];
      if (beam) mats.push(beam.material);
      var rec = { group: grp, mesh: grp, mats: mats, ring: ring, ringMat: ringMat, body: body, beam: beam, data: p, phase: Math.random() * 6.28 };
      markers.push(rec);
      return rec;
    }

    function makeArc(a) {
      var A = llVec(a.from.lat, a.from.lon, 1.005), B = llVec(a.to.lat, a.to.lon, 1.005);
      var dist = A.distanceTo(B);
      var mid = A.clone().add(B).multiplyScalar(0.5).normalize().multiplyScalar(1 + dist * 0.55);
      var curve = new T.QuadraticBezierCurve3(A, mid, B);
      var pts = curve.getPoints(48);
      var g = new T.BufferGeometry();
      var pos = new Float32Array(pts.length * 3), cols = new Float32Array(pts.length * 3);
      var c1 = new T.Color(sevColor(a.score || a.max_score)), c2 = new T.Color(0x7fe8ff);
      for (var i = 0; i < pts.length; i++) {
        pos[i * 3] = pts[i].x; pos[i * 3 + 1] = pts[i].y; pos[i * 3 + 2] = pts[i].z;
        var t = i / (pts.length - 1), c = c2.clone().lerp(c1, 0.35 + 0.65 * t);
        cols[i * 3] = c.r; cols[i * 3 + 1] = c.g; cols[i * 3 + 2] = c.b;
      }
      setAttr(g, "position", new T.BufferAttribute(pos, 3));
      setAttr(g, "color", new T.BufferAttribute(cols, 3));
      var m = new T.LineBasicMaterial({ vertexColors: T.VertexColors, transparent: true, opacity: 0.85, depthWrite: false });
      var line = new T.Line(g, m);
      line.geometry.setDrawRange(0, 2);
      arcGroup.add(line);
      arcs.push({ line: line, mesh: line, mats: [m], geo: g, mat: m, curve: curve, t: 0, data: a });
    }

    /* ------------------------------------------------------------------ interaction ---- */
    var rot = { x: 0.32, y: -1.2 }, target = { x: 0.32, y: -1.2 };
    var vel = { x: 0, y: 0 }, drag = null, zoom = 3.15, zoomT = 3.15, autoRotate = true, idle = 0;
    var el = renderer.domElement;
    var hovered = null, pointer = { x: -9999, y: -9999, inside: false };

    function onDown(e) {
      drag = { x: e.clientX, y: e.clientY, id: e.pointerId };
      el.setPointerCapture && el.setPointerCapture(e.pointerId);
      autoRotate = false; idle = 0; el.classList.add("grabbing");
    }
    function onMove(e) {
      var r = el.getBoundingClientRect();
      pointer.x = e.clientX - r.left; pointer.y = e.clientY - r.top; pointer.inside = true;
      if (!drag) return;
      var dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      drag.x = e.clientX; drag.y = e.clientY;
      vel.y = dx * 0.0055; vel.x = dy * 0.0045;
      target.y += vel.y; target.x = clamp(target.x + vel.x, -1.15, 1.15);
    }
    function onUp(e) {
      drag = null; idle = 0; el.classList.remove("grabbing");
      el.releasePointerCapture && e.pointerId != null && el.releasePointerCapture(e.pointerId);
    }
    function onWheel(e) {
      if (e.ctrlKey) return;                                   // let the page zoom normally
      e.preventDefault();
      zoomT = clamp(zoomT + (e.deltaY > 0 ? 0.22 : -0.22), 1.85, 5.2);
    }
    function onLeave() { pointer.inside = false; setHover(null); }
    el.addEventListener("pointerdown", onDown);
    el.addEventListener("pointermove", onMove);
    el.addEventListener("pointerup", onUp);
    el.addEventListener("pointercancel", onUp);
    el.addEventListener("pointerleave", onLeave);
    el.addEventListener("wheel", onWheel, { passive: false });
    el.addEventListener("click", function () { if (hovered && opts.onSelect) opts.onSelect(hovered.data); });

    function setHover(m) {
      if (hovered === m) return;
      if (hovered) hovered.ring.scale.setScalar(1);
      hovered = m;
      container.classList.toggle("has-hover", !!m);
      if (opts.onHover) opts.onHover(m ? m.data : null, pointer.x, pointer.y);
    }

    /* nearest marker to the pointer, in screen space (cheap: ≤ a few dozen projections) */
    var vTmp = new V3();
    function pick() {
      if (!pointer.inside || !markers.length) return null;
      var best = null, bd = 22 * 22;
      for (var i = 0; i < markers.length; i++) {
        var m = markers[i];
        vTmp.copy(m.group.position);
        globe.localToWorld(vTmp);
        vTmp.project(camera);
        if (vTmp.z > 1) continue;
        var sx = (vTmp.x * 0.5 + 0.5) * W, sy = (-vTmp.y * 0.5 + 0.5) * H;
        var d = (sx - pointer.x) * (sx - pointer.x) + (sy - pointer.y) * (sy - pointer.y);
        if (d < bd) { bd = d; best = m; }
      }
      return best;
    }

    /* --------------------------------------------------------------------- animation ---- */
    var raf = 0, running = false, t0 = performance.now(), lastPick = 0;
    function frame(now) {
      raf = requestAnimationFrame(frame);
      var dt = Math.min(0.05, (now - t0) / 1000); t0 = now;
      var time = now * 0.001;

      // inertia + auto rotation
      if (!drag) {
        target.y += vel.y; vel.y *= 0.92;
        target.x = clamp(target.x + vel.x, -1.15, 1.15); vel.x *= 0.9;
        idle += dt;
        if (idle > 3.2 && Math.abs(vel.y) < 0.0008) autoRotate = true;
        if (autoRotate) target.y += dt * 0.055;
      }
      rot.x += (target.x - rot.x) * 0.12;
      rot.y += (target.y - rot.y) * 0.12;
      root.rotation.set(rot.x, rot.y, 0);
      zoom += (zoomT - zoom) * 0.12;
      camera.position.z = zoom;
      oceanMat.uniforms.uTime.value = time;
      if (dust) dust.rotation.y = time * 0.012;

      // marker pulses
      for (var i = 0; i < markers.length; i++) {
        var m = markers[i];
        var s = 1 + 0.55 * Math.sin(time * 1.7 + m.phase);
        m.ring.scale.setScalar(0.7 + (m.data.approximate ? 0.15 : 0.35) * s);
        m.ringMat.opacity = (m.data.approximate ? 0.14 : 0.30) + 0.30 * (0.5 + 0.5 * Math.sin(time * 1.7 + m.phase));
        if (m === hovered) { m.ring.scale.setScalar(1.55); m.ringMat.opacity = 0.85; }
        if (m.beam) m.beam.material.opacity = 0.18 + 0.22 * (0.5 + 0.5 * Math.sin(time * 2.4 + m.phase));
      }
      // arc growth
      for (var j = 0; j < arcs.length; j++) {
        var a = arcs[j];
        if (a.t < 1) {
          a.t = Math.min(1, a.t + dt * 1.15);
          var n = Math.max(2, Math.floor(a.t * 49));
          a.geo.setDrawRange(0, n);
        }
      }
      // hover pick (throttled)
      if (now - lastPick > 60) { lastPick = now; setHover(pick()); }

      renderer.render(scene, camera);
    }
    function start() { if (!running) { running = true; t0 = performance.now(); raf = requestAnimationFrame(frame); } }
    function stop() { running = false; if (raf) cancelAnimationFrame(raf); raf = 0; }

    var ro = null;
    function resize() {
      W = container.clientWidth || W; H = container.clientHeight || H;
      if (!W || !H) return;
      camera.aspect = W / H; camera.updateProjectionMatrix();
      renderer.setSize(W, H);
    }
    if (window.ResizeObserver) { ro = new ResizeObserver(resize); ro.observe(container); }
    window.addEventListener("resize", resize);

    /* public API -------------------------------------------------------------------------- */
    var api = {
      el: el,
      setData: function (data) {
        data = data || {};
        clearGroup(markerGroup, markers); clearGroup(arcGroup, arcs);
        var pts = (data.points || []).filter(function (p) {
          return p && isFinite(p.lat) && isFinite(p.lon) && Math.abs(p.lat) <= 90 && Math.abs(p.lon) <= 180;
        });
        for (var i = 0; i < pts.length; i++) makeMarker(pts[i]);
        var as = data.arcs || [];
        for (var j = 0; j < Math.min(as.length, 60); j++) {
          var a = as[j];
          if (a && a.from && a.to && isFinite(a.from.lat) && isFinite(a.to.lat)) makeArc(a);
        }
        start();
      },
      focus: function (lat, lon, zoomTo) {
        if (!isFinite(lat) || !isFinite(lon)) return;
        var r = faceRotation(lat, lon);
        // keep the yaw change on the shortest path from the current rotation
        var twoPi = Math.PI * 2, delta = ((r.y - rot.y) % twoPi + twoPi + Math.PI) % twoPi - Math.PI;
        target.y = rot.y + delta;
        target.x = clamp(r.x, -1.0, 1.0);
        autoRotate = false; idle = -6;
        if (zoomTo) zoomT = clamp(zoomTo, 1.85, 5.2);
        start();
      },
      setAutoRotate: function (v) { autoRotate = !!v; idle = 0; if (v) idle = 3.3; },
      zoomBy: function (f) { zoomT = clamp(zoomT * f, 1.85, 5.2); start(); },
      isSpinning: function () { return autoRotate; },
      resize: resize,
      start: start, stop: stop,
      count: function () { return { markers: markers.length, arcs: arcs.length }; },
      dispose: function () {
        stop();
        el.removeEventListener("pointerdown", onDown); el.removeEventListener("pointermove", onMove);
        el.removeEventListener("pointerup", onUp); el.removeEventListener("pointercancel", onUp);
        el.removeEventListener("pointerleave", onLeave); el.removeEventListener("wheel", onWheel);
        window.removeEventListener("resize", resize);
        if (ro) ro.disconnect();
        clearGroup(markerGroup, markers); clearGroup(arcGroup, arcs);
        for (var i = 0; i < disposables.length; i++) {
          var d = disposables[i];
          if (d.dispose) d.dispose();
        }
        disposables.length = 0;
        scene.traverse(function (o) { if (o.geometry) o.geometry.dispose(); });
        renderer.dispose();
        if (renderer.domElement.parentNode) renderer.domElement.parentNode.removeChild(renderer.domElement);
        renderer.forceContextLoss && renderer.forceContextLoss();
      }
    };
    start();
    return api;
  }

  window.MTGlobe = { create: create, llVec: llVec, faceRotation: faceRotation, sevColor: sevColor };
})();
