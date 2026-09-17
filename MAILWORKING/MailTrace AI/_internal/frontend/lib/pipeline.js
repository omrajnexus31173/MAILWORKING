/* MailTrace AI — investigation pipeline visualisation.
   The node graph is cosmetic; the STATE IS NOT. Every transition is driven by the NDJSON events
   streamed by /api/analyze/stream, which are emitted by the real analysis code — a stage can only
   complete when the work it names has actually finished, and the metrics shown under each node
   are the values the backend reported for that stage. */
(function () {
  "use strict";

  var STAGES = [
    { id: "ingest",   title: "Email received",        sub: "size / MIME parse" },
    { id: "headers",  title: "Header extraction",     sub: "RFC-5322 · received chain" },
    { id: "sender",   title: "Sender analysis",       sub: "from · reply-to · return-path" },
    { id: "domain",   title: "Domain analysis",       sub: "RDAP · age · registrar" },
    { id: "auth",     title: "Authentication check",  sub: "SPF · DKIM · DMARC" },
    { id: "urls",     title: "URL analysis",          sub: "links · attachments" },
    { id: "content",  title: "Content analysis",      sub: "NLP · social engineering" },
    { id: "ai",       title: "AI threat detection",   sub: "classification · scoring" },
    { id: "geo",      title: "Geolocation",           sub: "GeoIP · ASN · Tor · RDAP" },
    { id: "forensic", title: "Forensic correlation",  sub: "attribution · confidence" },
    { id: "verdict",  title: "Final assessment",      sub: "verdict · report" }
  ];
  var esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  };

  /* metric line for a completed stage — only real values, nothing synthesised */
  function metrics(id, p) {
    function n(v, suffix) { return v == null || v === "" ? null : esc(v) + (suffix || ""); }
    switch (id) {
      case "ingest":   return join([p.bytes != null ? (p.bytes + " bytes") : null]);
      case "headers":  return join([p.hops != null ? p.hops + " relay hop(s)" : null, p.findings != null ? p.findings + " header findings" : null]);
      case "sender":   return join([p.address ? esc(p.address) : null, p.reply_to ? "reply-to differs" : null]);
      case "domain":   return p.phase === "enriched"
        ? join([p.domain ? esc(p.domain) : null, p.age_days != null ? p.age_days + " days old" : (p.rdap === false ? "no RDAP record" : null), p.resolves === false ? "does not resolve" : null, p.url_domains ? p.url_domains + " link domain(s)" : null])
        : join([p.domain ? esc(p.domain) : null, p.freemail ? "free webmail" : "registered domain identified", "RDAP pending"]);
      case "auth":     return join(["SPF " + (p.spf || "none"), "DKIM " + (p.dkim || "none"), "DMARC " + (p.dmarc || "none")]);
      case "urls":     return join([p.urls != null ? p.urls + " URL(s)" : null, p.risky_urls ? p.risky_urls + " risky" : null, p.attachments ? p.attachments + " attachment(s)" : null]);
      case "content":  return join([p.phishing_probability != null ? (Math.round(p.phishing_probability * 100) + "% phishing probability") : null, p.cue_score != null ? "cue score " + p.cue_score : null, (p.bec_patterns || []).length ? p.bec_patterns.length + " BEC pattern(s)" : null]);
      case "ai":       return join([p.score != null ? "risk " + p.score + "/100" : null, p.label ? esc(p.label) : null, p.critical ? p.critical + " critical finding(s)" : null]);
      case "geo":      return join([p.origin_ip ? esc(p.origin_ip) : "no public origin IP",
                                    p.country ? esc(p.city ? p.city + ", " + p.country : p.country) : "unresolved",
                                    p.precision ? p.precision + "-level" : null,
                                    p.resolved != null ? p.resolved + "/" + p.total + " resolved" : null,
                                    p.tor ? "Tor exit" : null]);
      case "forensic": return join([p.scenario_label ? esc(p.scenario_label) : null, p.confidence != null ? "confidence " + Math.round(p.confidence * 100) + "%" : null, p.findings != null ? p.findings + " findings" : null]);
      case "verdict":  return join([p.threat ? esc(String(p.threat).replace(/_/g, " ")) : null, p.nodes != null ? p.nodes + " graph nodes" : null, p.timing_ms != null ? p.timing_ms + " ms" : null]);
      default: return "";
    }
  }
  function join(a) { return a.filter(Boolean).slice(0, 3).join(" · "); }

  function create(container, opts) {
    opts = opts || {};
    var state = {}, order = STAGES.map(function (s) { return s.id; });
    var startedAt = Date.now();

    function layout() {
      // two-row zig-zag on wide screens, single column when narrow.
      // X is computed in pixels (half a node wide of padding) so nodes never overflow the card.
      var Wc = container.clientWidth || 900, nodeW = 190, pad = Math.min(nodeW / 2 + 8, Wc / 8);
      var wide = Wc > 720;
      return STAGES.map(function (s, i) {
        if (!wide) return { x: Wc / 2, y: i / (STAGES.length - 1), px: true };
        var row = i % 2, col = Math.floor(i / 2);
        return { x: pad + col * ((Wc - 2 * pad) / 5), y: row === 0 ? 0.24 : 0.76, px: true };
      });
    }

    function render() {
      var pos = layout(), wide = container.clientWidth > 720;
      var Wc = container.clientWidth || 900;
      var svg = '<svg class="pipe-links" viewBox="0 0 ' + Wc + ' 100" preserveAspectRatio="none">';
      for (var i = 0; i < pos.length - 1; i++) {
        var a = pos[i], b = pos[i + 1];
        var mx = (a.x + b.x) / 2;
        var d = "M " + a.x + " " + (a.y * 100) +
          " C " + mx + " " + (a.y * 100) + " " + mx + " " + (b.y * 100) + " " + b.x + " " + (b.y * 100);
        var st = state[STAGES[i + 1].id] || "idle";
        var cls = st === "done" ? "done" : st === "run" ? "run" : "";
        svg += '<path class="pipe-link ' + cls + '" d="' + d + '" vector-effect="non-scaling-stroke"/>';
        if (st === "run") svg += '<path class="pipe-link flow" d="' + d + '" vector-effect="non-scaling-stroke"/>';
      }
      svg += "</svg>";

      var html = STAGES.map(function (s, i) {
        var st = state[s.id] || "idle", p = (opts.payloads || {})[s.id] || {};
        var m = st === "done" ? metrics(s.id, p) : (st === "run" ? "processing…" : "queued");
        return '<div class="pipe-node ' + st + '" style="left:' + pos[i].x.toFixed(1) + 'px;top:' + (pos[i].y * 100).toFixed(2) + '%" data-id="' + s.id + '">' +
          '<div class="pipe-core"><span class="pipe-idx">' + (i + 1) + '</span><span class="pipe-tick">' + (st === "done" ? "✓" : st === "run" ? "" : "") + '</span></div>' +
          '<div class="pipe-txt"><b>' + esc(s.title) + '</b><span class="pipe-sub">' + esc(s.sub) + '</span><span class="pipe-metric">' + m + '</span></div>' +
          "</div>";
      }).join("");

      container.innerHTML = svg + html +
        '<div class="pipe-foot"><span class="pipe-elapsed" id="pipe-elapsed">elapsed ' + ((Date.now() - startedAt) / 1000).toFixed(1) + "s</span>" +
        '<span class="pipe-note">stages complete as the backend reports them — nothing is simulated</span></div>';
      if (!wide) container.classList.add("pipe-vertical"); else container.classList.remove("pipe-vertical");
    }

    var timer = null;
    function tick() {
      var el = container.querySelector("#pipe-elapsed");
      if (el) el.textContent = "elapsed " + ((Date.now() - startedAt) / 1000).toFixed(1) + "s";
    }
    render();
    timer = setInterval(tick, 100);

    return {
      stage: function (id, status, payload) {
        if (order.indexOf(id) < 0) return;
        state[id] = status === "run" ? "run" : (status === "fail" ? "fail" : "done");
        opts.payloads = opts.payloads || {};
        if (payload) opts.payloads[id] = Object.assign(opts.payloads[id] || {}, payload);
        render();
      },
      note: function (text) {
        var el = container.querySelector(".pipe-note");
        if (el) el.textContent = text;
      },
      fail: function (msg) {
        state[Object.keys(state).pop() || "ingest"] = "fail";
        container.insertAdjacentHTML("beforeend", '<div class="pipe-error">' + esc(msg || "Analysis failed") + "</div>");
        clearInterval(timer);
      },
      done: function () { clearInterval(timer); },
      dispose: function () { clearInterval(timer); container.innerHTML = ""; },
      stages: STAGES
    };
  }

  window.MTPipeline = { create: create, STAGES: STAGES };
})();
