/* MailTrace AI — procedural 3D snake (background environment object).
   A real WebGL object built with the vendored Three.js r97: a tapering body of ~60-80 segments
   that follows a wander-and-return steering model with a serpentine lateral wave, so the motion is
   continuous and procedural instead of a short looped clip.

   Rules it follows:
     • never intercepts pointer events, sits behind the UI (z-index below the app shell)
     • pauses when the tab is hidden, when the layer is scrolled out of view, and when the
       capability tier is "low" or prefers-reduced-motion is set
     • disposes every geometry / material / renderer on dispose()
*/
(function () {
  "use strict";
  var w = window;

  function rnd(a, b) { return a + Math.random() * (b - a); }
  function clamp(v, a, b) { return v < a ? a : v > b ? b : v; }

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
    var camera = new T.PerspectiveCamera(46, 1, 0.1, 200);
    camera.position.set(0, 0, 26);

    /* ------------------------------------------------------------------ lights ---- */
    scene.add(new T.AmbientLight(0x24405c, 1.15));
    var key = new T.PointLight(0x4de3d4, 1.5, 90); key.position.set(12, 10, 18); scene.add(key);
    var rim = new T.PointLight(0x6f8cff, 1.0, 110); rim.position.set(-18, -8, 12); scene.add(rim);

    /* ------------------------------------------------------------------- body ---- */
    var N = tier === "high" ? 78 : 58;                            // segment count (long body)
    var SEG = 0.62;                                               // spacing between segment centres
    var group = new T.Group(); scene.add(group);
    var geo = new T.SphereGeometry(1, tier === "high" ? 14 : 10, tier === "high" ? 12 : 8);

    // a short palette, shared across segments: head is brighter, tail sinks into the dark
    var HEAD = new T.Color(0x7ffff0), MID = new T.Color(0x2fa8c8), TAIL = new T.Color(0x1d3f77);
    var mats = [];
    for (var m = 0; m < 12; m++) {
      var t = m / 11, c = t < 0.5 ? HEAD.clone().lerp(MID, t * 2) : MID.clone().lerp(TAIL, (t - 0.5) * 2);
      mats.push(new T.MeshPhongMaterial({
        color: c, emissive: c.clone().multiplyScalar(0.32), specular: 0x9fd8ff, shininess: 55,
        transparent: true, opacity: 0.92, depthWrite: true
      }));
    }
    var segs = [];
    for (var i = 0; i < N; i++) {
      var mesh = new T.Mesh(geo, mats[Math.min(11, Math.floor(i / N * 12))]);
      group.add(mesh); segs.push(mesh);
    }
    // eyes + a soft head glow so it reads as a creature, not a string of beads
    var head = new T.Mesh(new T.SphereGeometry(1.18, 16, 14), new T.MeshPhongMaterial({
      color: 0x9ffff4, emissive: 0x2ad9c8, emissiveIntensity: 0.9, shininess: 90, transparent: true, opacity: 0.95
    }));
    group.add(head);
    var glow = new T.Mesh(new T.SphereGeometry(2.3, 16, 14), new T.MeshBasicMaterial({
      color: 0x4de3d4, transparent: true, opacity: 0.085, depthWrite: false, blending: T.AdditiveBlending
    }));
    group.add(glow);
    [-0.42, 0.42].forEach(function (ox) {
      var eye = new T.Mesh(new T.SphereGeometry(0.17, 10, 8), new T.MeshBasicMaterial({ color: 0x061018 }));
      eye.userData.offset = ox; group.add(eye);
    });
    var eyes = group.children.filter(function (c) { return c.userData && c.userData.offset !== undefined; });

    /* --------------------------------------------------------------- particles ---- */
    var dust = null;
    if (tier === "high") {
      var dn = 220, pos = new Float32Array(dn * 3);
      for (var d = 0; d < dn; d++) {
        pos[d * 3] = rnd(-26, 26); pos[d * 3 + 1] = rnd(-16, 16); pos[d * 3 + 2] = rnd(-14, 8);
      }
      var dg = new T.BufferGeometry();
      if (dg.setAttribute) dg.setAttribute("position", new T.BufferAttribute(pos, 3));
      else dg.addAttribute("position", new T.BufferAttribute(pos, 3));
      dust = new T.Points(dg, new T.PointsMaterial({
        color: 0x8fd8ff, size: 0.09, transparent: true, opacity: 0.5, depthWrite: false, blending: T.AdditiveBlending
      }));
      scene.add(dust);
    }

    /* ------------------------------------------------------------- body dynamics ---- */
    var pts = [];
    for (var k = 0; k < N; k++) pts.push(new T.Vector3(-k * SEG, 0, 0));
    var headPos = new T.Vector3(0, 0, 0);
    var vel = new T.Vector3(0.9, 0.2, 0);
    var target = new T.Vector3(rnd(6, 14), rnd(-4, 4), rnd(-4, 4));
    var bounds = { x: 17, y: 9.5, z: 7 };
    var speed = 3.1, turn = 0;
    var t = 0, nextTarget = 0;

    function pickTarget(now) {
      // bias forward so the body rarely folds back over itself
      var dir = Math.random() < 0.65 ? 1 : -1;
      target.set(clamp(headPos.x + dir * rnd(6, 16), -bounds.x, bounds.x),
                 clamp(headPos.y + rnd(-7, 7), -bounds.y, bounds.y),
                 clamp(headPos.z + rnd(-6, 6), -bounds.z, bounds.z));
      nextTarget = now + rnd(2.4, 5.2);
    }

    function step(dt, now) {
      t += dt;
      if (now > nextTarget || headPos.distanceTo(target) < 2.2) pickTarget(now);

      // steering: seek the target, smooth the turn, keep a slow vertical drift
      var desired = target.clone().sub(headPos);
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
      var dirv = vel.clone().normalize();
      var side = new T.Vector3(-dirv.y, dirv.x, 0);
      if (side.lengthSq() < 0.0001) side.set(0, 1, 0);
      side.normalize();

      // head: position + wave
      pts[0].copy(headPos).addScaledVector(side, Math.sin(t * 2.1) * 0.42);
      // follow-the-leader with a fixed spacing → the body trails naturally
      for (var i = 1; i < N; i++) {
        var prev = pts[i - 1], p = pts[i];
        var off = p.clone().sub(prev);
        var len = off.length() || 0.0001;
        off.multiplyScalar(SEG / len);
        p.copy(prev).add(off);
        // add the slither: each segment lags a little further in the wave phase
        p.addScaledVector(side, Math.sin(t * 2.1 - i * 0.34) * 0.30 * (1 - i / N * 0.55));
        p.y += Math.sin(t * 1.15 - i * 0.19) * 0.05;
      }

      // push the chain into the meshes
      for (var j = 0; j < N; j++) {
        var s = segs[j], q = pts[j];
        s.position.copy(q);
        var taper = 1 - Math.pow(j / N, 1.35) * 0.78;             // thick at the head, thin at the tail
        var bulge = 1 + Math.sin(t * 2.1 - j * 0.34) * 0.05;
        s.scale.setScalar(0.62 * taper * bulge);
      }
      head.position.copy(pts[0]);
      var hdir = pts[0].clone().sub(pts[1]).normalize();
      head.lookAt(pts[0].clone().add(hdir));
      head.scale.setScalar(0.78);
      glow.position.copy(pts[0]);
      glow.material.opacity = 0.06 + 0.035 * (0.5 + 0.5 * Math.sin(t * 1.7));
      eyes.forEach(function (e) {
        var up = new T.Vector3(0, 1, 0), right = new T.Vector3().crossVectors(hdir, up).normalize();
        var realUp = new T.Vector3().crossVectors(right, hdir).normalize();
        e.position.copy(pts[0]).addScaledVector(hdir, 0.55).addScaledVector(right, e.userData.offset).addScaledVector(realUp, 0.28);
      });
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
      // keep the whole body in frame on narrow viewports
      camera.position.z = clamp(30 - (Wc / Hc) * 6, 20, 34);
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

    resize(); start();

    return {
      dispose: function () {
        dead = true; running = false;
        if (raf) cancelAnimationFrame(raf);
        w.removeEventListener("resize", onResize);
        document.removeEventListener("visibilitychange", onVis);
        if (io) io.disconnect();
        scene.traverse(function (o) { if (o.geometry) o.geometry.dispose(); });
        mats.forEach(function (mm) { mm.dispose(); });
        head.material.dispose(); glow.material.dispose();
        eyes.forEach(function (e) { e.material.dispose(); });
        if (dust) dust.material.dispose();
        renderer.dispose();
        if (renderer.domElement && renderer.domElement.parentNode) renderer.domElement.parentNode.removeChild(renderer.domElement);
        group.clear ? group.clear() : null;
      },
      stats: function () { return { segments: N, quality: tier, running: running }; },
      // used by the headless tests to prove the body is actually moving and stays connected
      sample: function () {
        var d = 0;
        for (var i = 1; i < N; i++) d += pts[i].distanceTo(pts[i - 1]);
        return { head: pts[0].toArray(), tail: pts[N - 1].toArray(), chain: d, spacing: d / (N - 1) };
      }
    };
  }

  w.MTSnake = { mount: mount };
})();
