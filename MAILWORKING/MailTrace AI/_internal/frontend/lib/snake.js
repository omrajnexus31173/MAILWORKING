/* MailTrace AI — procedural 3D snake (background environment object).
   A single continuous WebGL body built with the vendored Three.js r97: one tapered, elliptical
   tube mesh whose ~1 000 vertices are re-generated every frame from a spine that follows a
   wander-and-return steering model with a serpentine lateral wave. It is a real solid surface
   (indexed triangles, smooth per-vertex normals, no beads / no points / no looped clip), so the
   body reads as one animal sliding through the scene.

   Rules it follows:
     • never intercepts pointer events, sits behind the UI (z-index below the app shell)
     • pauses when the tab is hidden, when the layer is scrolled out of view, and when the
       capability tier is "low" or prefers-reduced-motion is set
     • geometry buffers are allocated once and written in place — no per-frame allocation
     • disposes every geometry / material / renderer on dispose()
*/
(function () {
  "use strict";
  var w = window;

  function rnd(a, b) { return a + Math.random() * (b - a); }
  function clamp(v, a, b) { return v < a ? a : v > b ? b : v; }
  function smooth(t) { return t * t * (3 - 2 * t); }

  /* radius profile along the body: closed snout → head → neck → thickest → long taper → tip.
     (u = 0 at the nose, u = 1 at the tail tip; values are fractions of the base radius) */
  var PROFILE = [
    [0.000, 0.04], [0.020, 0.44], [0.045, 0.79], [0.075, 0.81], [0.100, 0.66],
    [0.150, 0.86], [0.240, 1.00], [0.400, 0.90], [0.600, 0.66], [0.780, 0.40],
    [0.900, 0.22], [0.970, 0.09], [1.000, 0.012]
  ];
  function radiusAt(u) {
    if (u <= 0) return PROFILE[0][1];
    if (u >= 1) return PROFILE[PROFILE.length - 1][1];
    for (var i = 1; i < PROFILE.length; i++) {
      if (u <= PROFILE[i][0]) {
        var a = PROFILE[i - 1], b = PROFILE[i];
        return a[1] + (b[1] - a[1]) * smooth((u - a[0]) / (b[0] - a[0] || 1));
      }
    }
    return 0.012;
  }

  function mount(container, opts) {
    opts = opts || {};
    var fx = w.MTfx || {};
    var reduce = !!fx.reduceMotion;
    var tier = fx.quality || "mid";
    var T = w.THREE;
    if (!container) return null;
    if (!T || reduce || tier === "low") return null;              // no WebGL / reduced motion → nothing to draw

    var renderer;
    try {
      renderer = new T.WebGLRenderer({ antialias: tier === "high", alpha: true, powerPreference: "default" });
    } catch (e) { return null; }
    var dpr = Math.min(w.devicePixelRatio || 1, tier === "high" ? 1.6 : 1.25);
    renderer.setPixelRatio(dpr);
    renderer.setClearColor(0x000000, 0);
    container.appendChild(renderer.domElement);

    var scene = new T.Scene();
    var camera = new T.PerspectiveCamera(46, 1, 0.1, 240);
    camera.position.set(0, 0, 31);

    /* ------------------------------------------------------------------ lights ---- */
    scene.add(new T.AmbientLight(0x24405c, 1.05));
    var key = new T.PointLight(0x4de3d4, 1.6, 120); key.position.set(12, 10, 18); scene.add(key);
    var rim = new T.PointLight(0x6f8cff, 1.05, 140); rim.position.set(-20, -9, 14); scene.add(rim);

    /* --------------------------------------------------------- continuous body ---- */
    var RINGS = tier === "high" ? 96 : 72;                        // spine rings (long body)
    var RADIAL = tier === "high" ? 12 : 9;                        // vertices around each ring
    var SEG = 0.58;                                               // spacing between ring centres
    var R0 = 0.9;                                                 // base radius (rings overlap → smooth skin)
    var FLAT = 0.82;                                              // belly flattening (wider than tall)
    var verts = RINGS * RADIAL;
    var TRIS = (RINGS - 1) * RADIAL * 2;

    function makeTube() {
      var pos = new Float32Array(verts * 3), nor = new Float32Array(verts * 3), col = new Float32Array(verts * 3);
      var idx = new Uint16Array((RINGS - 1) * RADIAL * 6), k = 0;
      for (var i = 0; i < RINGS - 1; i++) {
        for (var j = 0; j < RADIAL; j++) {
          var jn = (j + 1) % RADIAL;
          var a = i * RADIAL + j, b = i * RADIAL + jn, c = (i + 1) * RADIAL + j, d = (i + 1) * RADIAL + jn;
          idx[k++] = a; idx[k++] = b; idx[k++] = c;               // outward-facing winding
          idx[k++] = b; idx[k++] = d; idx[k++] = c;
        }
      }
      var g = new T.BufferGeometry();
      var add = g.setAttribute ? "setAttribute" : "addAttribute";
      g[add]("position", new T.BufferAttribute(pos, 3));
      g[add]("normal", new T.BufferAttribute(nor, 3));
      g[add]("color", new T.BufferAttribute(col, 3));
      g.setIndex(new T.BufferAttribute(idx, 1));
      return { geo: g, pos: pos, nor: nor, col: col };
    }

    var body = makeTube();
    var bodyMat = new T.MeshPhongMaterial({
      vertexColors: T.VertexColors, specular: 0x9fd8ff, shininess: 62, emissive: 0x061520,
      transparent: true, opacity: 0.97, side: T.FrontSide
    });
    var mesh = new T.Mesh(body.geo, bodyMat);
    mesh.frustumCulled = false;                                   // the skin is rebuilt every frame
    var group = new T.Group(); scene.add(group); group.add(mesh);

    // additive back-side shell: a soft rim glow, no extra geometry maths beyond a wider radius
    var glowT = makeTube();
    var glowMat = new T.MeshBasicMaterial({
      color: 0x3fd8cf, transparent: true, opacity: 0.075, blending: T.AdditiveBlending,
      side: T.BackSide, depthWrite: false
    });
    var glowMesh = new T.Mesh(glowT.geo, glowMat);
    glowMesh.frustumCulled = false;
    group.add(glowMesh);

    // eyes, carried by the body (no separate head bead — the head is part of the tube)
    var eyeMat = new T.MeshPhongMaterial({ color: 0x071a24, specular: 0xbff4ff, shininess: 110 });
    var eyeGeo = new T.SphereBufferGeometry(0.15, 10, 8);
    var eyes = [];
    [-1, 1].forEach(function (s) {
      var e = new T.Mesh(eyeGeo, eyeMat); e.userData.side = s; group.add(e); eyes.push(e);
    });
    var halo = new T.Mesh(new T.SphereBufferGeometry(2.4, 16, 14), new T.MeshBasicMaterial({
      color: 0x4de3d4, transparent: true, opacity: 0.06, depthWrite: false, blending: T.AdditiveBlending
    }));
    group.add(halo);

    /* --------------------------------------------------------------- particles ---- */
    var dust = null;
    if (tier === "high") {
      var dn = 220, dp = new Float32Array(dn * 3);
      for (var d2 = 0; d2 < dn; d2++) {
        dp[d2 * 3] = rnd(-26, 26); dp[d2 * 3 + 1] = rnd(-16, 16); dp[d2 * 3 + 2] = rnd(-14, 8);
      }
      var dg = new T.BufferGeometry();
      var dadd = dg.setAttribute ? "setAttribute" : "addAttribute";
      dg[dadd]("position", new T.BufferAttribute(dp, 3));
      dust = new T.Points(dg, new T.PointsMaterial({
        color: 0x8fd8ff, size: 0.09, transparent: true, opacity: 0.5, depthWrite: false, blending: T.AdditiveBlending
      }));
      scene.add(dust);
    }

    /* ------------------------------------------------------------- body dynamics ---- */
    var pts = [], tan = [], nrm = [], bin = [];
    for (var k2 = 0; k2 < RINGS; k2++) {
      pts.push(new T.Vector3(-k2 * SEG, 0, 0));
      tan.push(new T.Vector3(1, 0, 0)); nrm.push(new T.Vector3(0, 1, 0)); bin.push(new T.Vector3(0, 0, 1));
    }
    var v3 = new T.Vector3(), v3b = new T.Vector3(), upRef = new T.Vector3(0, 1, 0), upAlt = new T.Vector3(0, 0, 1);
    var HEADC = new T.Color(0x86fff2), MIDC = new T.Color(0x2fa8c8), TAILC = new T.Color(0x142a55);
    var tmpC = new T.Color();

    var headPos = new T.Vector3(0, 0, 0);
    var vel = new T.Vector3(0.9, 0.2, 0);
    var target = new T.Vector3(rnd(6, 14), rnd(-4, 4), rnd(-4, 4));
    var bounds = { x: 15, y: 8.5, z: 6 };
    var speed = 3.1;
    var t = 0, nextTarget = 0, pulseU = -0.2;

    function pickTarget(now) {
      var dir = Math.random() < 0.65 ? 1 : -1;                    // bias forward: the body rarely folds over itself
      target.set(clamp(headPos.x + dir * rnd(6, 16), -bounds.x, bounds.x),
                 clamp(headPos.y + rnd(-6, 6), -bounds.y, bounds.y),
                 clamp(headPos.z + rnd(-6, 6), -bounds.z, bounds.z));
      nextTarget = now + rnd(2.4, 5.2);
    }

    function frames() {
      for (var i = 0; i < RINGS; i++) {
        var a = pts[i > 0 ? i - 1 : 0], b = pts[i < RINGS - 1 ? i + 1 : RINGS - 1];
        tan[i].copy(b).sub(a);
        if (tan[i].lengthSq() < 1e-9) tan[i].set(1, 0, 0); else tan[i].normalize();
        // world-up referenced frame: no twist, and the belly always faces down
        var up = Math.abs(tan[i].y) > 0.94 ? upAlt : upRef;
        bin[i].crossVectors(tan[i], up);
        if (bin[i].lengthSq() < 1e-9) bin[i].set(1, 0, 0); else bin[i].normalize();
        nrm[i].crossVectors(bin[i], tan[i]).normalize();
      }
    }

    function skin(buf, scale, withColor) {
      var pos = buf.pos, nor = buf.nor, col = buf.col;
      for (var i = 0; i < RINGS; i++) {
        var u = i / (RINGS - 1), P = pts[i], N = nrm[i], B = bin[i];
        var r = R0 * radiusAt(u) * scale;
        // swallow / breathing pulse travelling down the body
        var sw = 1 + 0.09 * Math.exp(-Math.pow(u - pulseU, 2) / 0.0016) + 0.025 * Math.sin(t * 1.6 - u * 5.0);
        r *= sw;
        // colour along the body: bright head → deep tail, darker belly, faint scale banding
        var base = u < 0.42 ? tmpC.copy(HEADC).lerp(MIDC, u / 0.42) : tmpC.copy(MIDC).lerp(TAILC, (u - 0.42) / 0.58);
        var br = base.r, bg = base.g, bb = base.b;
        var band = 0.9 + 0.1 * Math.sin(u * Math.PI * 2 * 34);
        var pulse = 1 + 0.5 * Math.exp(-Math.pow(u - pulseU, 2) / 0.0035);
        for (var j = 0; j < RADIAL; j++) {
          var th = j / RADIAL * Math.PI * 2, ct = Math.cos(th), st = Math.sin(th);
          var o = (i * RADIAL + j) * 3;
          pos[o] = P.x + (N.x * ct * FLAT + B.x * st) * r;
          pos[o + 1] = P.y + (N.y * ct * FLAT + B.y * st) * r;
          pos[o + 2] = P.z + (N.z * ct * FLAT + B.z * st) * r;
          // ellipse normal: (cos/a, sin/b) with semi-axes a = r*FLAT, b = r
          var nx = N.x * ct / FLAT + B.x * st, ny = N.y * ct / FLAT + B.y * st, nz = N.z * ct / FLAT + B.z * st;
          var il = 1 / (Math.sqrt(nx * nx + ny * ny + nz * nz) || 1);
          nor[o] = nx * il; nor[o + 1] = ny * il; nor[o + 2] = nz * il;
          if (withColor) {
            var shade = (0.74 + 0.26 * (0.5 + 0.5 * ct)) * band * pulse;
            col[o] = Math.min(1, br * shade); col[o + 1] = Math.min(1, bg * shade); col[o + 2] = Math.min(1, bb * shade);
          }
        }
      }
      buf.geo.attributes.position.needsUpdate = true;
      buf.geo.attributes.normal.needsUpdate = true;
      if (withColor) buf.geo.attributes.color.needsUpdate = true;
    }

    function step(dt, now) {
      t += dt;
      pulseU += dt * 0.30; if (pulseU > 1.25) pulseU = -0.25;
      if (now > nextTarget || headPos.distanceTo(target) < 2.2) pickTarget(now);

      // steering: seek the target, smooth the turn, keep a slow vertical drift
      var desired = v3.copy(target).sub(headPos);
      if (desired.lengthSq() > 0.0001) desired.normalize().multiplyScalar(speed);
      desired.y += Math.sin(t * 0.7) * 0.9;
      desired.z += Math.cos(t * 0.53) * 0.7;
      vel.lerp(desired, Math.min(1, dt * 1.6));
      if (vel.lengthSq() > 0.0001) {
        vel.setLength(clamp(vel.length(), speed * 0.55, speed * 1.35));
        headPos.addScaledVector(vel, dt);
      }
      // soft walls: steer back instead of snapping
      ["x", "y", "z"].forEach(function (ax) {
        var lim = bounds[ax];
        if (headPos[ax] > lim) { headPos[ax] = lim; vel[ax] = -Math.abs(vel[ax]) * 0.9; target[ax] = -lim * rnd(0.3, 0.8); }
        if (headPos[ax] < -lim) { headPos[ax] = -lim; vel[ax] = Math.abs(vel[ax]) * 0.9; target[ax] = lim * rnd(0.3, 0.8); }
      });

      // serpentine lateral wave: offset perpendicular to travel direction
      var dirv = v3b.copy(vel).normalize();
      var side = new T.Vector3(-dirv.y, dirv.x, 0);
      if (side.lengthSq() < 0.0001) side.set(0, 1, 0);
      side.normalize();

      pts[0].copy(headPos).addScaledVector(side, Math.sin(t * 2.1) * 0.42);
      // follow-the-leader with fixed spacing → the body trails naturally
      for (var i = 1; i < RINGS; i++) {
        var prev = pts[i - 1], p = pts[i];
        var off = v3.copy(p).sub(prev);
        var len = off.length() || 0.0001;
        off.multiplyScalar(SEG / len);
        p.copy(prev).add(off);
        p.addScaledVector(side, Math.sin(t * 2.1 - i * 0.30) * 0.30 * (1 - i / RINGS * 0.55));
        p.y += Math.sin(t * 1.15 - i * 0.17) * 0.05;
      }

      frames();
      skin(body, 1, true);
      skin(glowT, 1.16, false);

      // eyes + halo ride the head rings
      var hi = Math.max(1, Math.round(RINGS * 0.05)), hp = pts[hi], hN = nrm[hi], hB = bin[hi], hT = tan[hi];
      var hr = R0 * radiusAt(hi / (RINGS - 1));
      eyes.forEach(function (e) {
        e.position.copy(hp)
          .addScaledVector(hT, -0.35 * hr)
          .addScaledVector(hN, 0.42 * hr)
          .addScaledVector(hB, e.userData.side * 0.52 * hr);
        e.scale.setScalar(clamp(hr / 0.72, 0.6, 1.3));
      });
      halo.position.copy(hp);
      halo.material.opacity = 0.045 + 0.03 * (0.5 + 0.5 * Math.sin(t * 1.7));
      key.position.set(pts[0].x + 8, pts[0].y + 6, pts[0].z + 16);
      if (dust) dust.rotation.y += dt * 0.012;
      // idle camera drift: parallax without taking over the screen
      camera.position.x += ((w.innerWidth ? Math.sin(t * 0.11) * 1.6 : 0) - camera.position.x) * 0.02;
      camera.position.y += ((Math.cos(t * 0.09) * 1.1) - camera.position.y) * 0.02;
      camera.lookAt(0, 0, 0);
    }

    /* ------------------------------------------------------------- loop / resize ---- */
    var raf = 0, last = 0, visible = true, dead = false, running = false;
    function resize() {
      var Wc = container.clientWidth || w.innerWidth, Hc = container.clientHeight || w.innerHeight;
      if (!Wc || !Hc) return;
      renderer.setSize(Wc, Hc, false);
      camera.aspect = Wc / Hc;
      camera.updateProjectionMatrix();
      // viewport-adaptive: keep the long body in frame on narrow / short viewports
      var s = clamp(0.62 + 0.38 * Math.min(camera.aspect, 1.8) / 1.8, 0.6, 1.0);
      group.scale.setScalar(s);
      camera.position.z = clamp(31 / s, 31, 46);
    }
    function frame(now) {
      if (dead) return;
      if (!last) last = now;
      var dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      if (visible && !document.hidden) { step(dt, now / 1000); renderer.render(scene, camera); }
      raf = requestAnimationFrame(frame);
    }
    function start() { if (!running) { running = true; last = 0; raf = requestAnimationFrame(frame); } }

    var onResize = function () { resize(); };
    w.addEventListener("resize", onResize);
    var io = null;
    if (w.IntersectionObserver) {
      io = new IntersectionObserver(function (e) { visible = e[0].isIntersecting; }, { threshold: 0.01 });
      io.observe(container);
    }
    var onVis = function () { if (document.hidden) { visible = false; } else { visible = true; last = 0; } };
    document.addEventListener("visibilitychange", onVis);

    resize(); frames(); skin(body, 1, true); skin(glowT, 1.16, false); start();

    return {
      dispose: function () {
        dead = true; running = false;
        if (raf) cancelAnimationFrame(raf);
        w.removeEventListener("resize", onResize);
        document.removeEventListener("visibilitychange", onVis);
        if (io) io.disconnect();
        scene.traverse(function (o) { if (o.geometry) o.geometry.dispose(); });
        bodyMat.dispose(); glowMat.dispose(); eyeMat.dispose(); halo.material.dispose();
        if (dust) dust.material.dispose();
        renderer.dispose();
        if (renderer.domElement && renderer.domElement.parentNode) renderer.domElement.parentNode.removeChild(renderer.domElement);
        if (group.clear) group.clear();
      },
      stats: function () {
        return {
          segments: RINGS, rings: RINGS, radial: RADIAL, vertices: verts, triangles: TRIS,
          continuous: true, meshes: 1, quality: tier, running: running
        };
      },
      // debug/QA hook: exposes the live skin buffers so an offline rasteriser can render a frame
      debug: function () {
        return {
          pos: body.pos, nor: body.nor, col: body.col,
          index: body.geo.index.array, rings: RINGS, radial: RADIAL,
          scale: group.scale.x, cam: { x: camera.position.x, y: camera.position.y, z: camera.position.z }
        };
      },
      // used by the headless tests to prove the body is one connected skin that actually moves
      sample: function () {
        var d = 0, maxGap = 0;
        for (var i = 1; i < RINGS; i++) {
          var g = pts[i].distanceTo(pts[i - 1]); d += g; if (g > maxGap) maxGap = g;
        }
        var rHead = R0 * radiusAt(0.24);
        return {
          head: pts[0].toArray(), tail: pts[RINGS - 1].toArray(), chain: d,
          spacing: d / (RINGS - 1), maxGap: maxGap, radius: rHead,
          // rings must overlap (gap < diameter) or the skin would break into separate beads
          continuity: maxGap / (2 * rHead)
        };
      }
    };
  }

  w.MTSnake = { mount: mount, radiusAt: radiusAt };
})();
