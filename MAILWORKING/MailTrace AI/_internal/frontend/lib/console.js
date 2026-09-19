/* MailTrace AI — accounts console, notification centre, modal dialogs.
   Real data only: every status, count and timestamp comes from the API. No simulated scanning. */
(function () {
  "use strict";
  var w = window;
  var C = null;                       // bound helpers from app.js ($ , esc, api, toast, view …)
  var state = { items: [], unread: 0, open: false, accounts: [], monitor: null, timer: 0, poll: 0 };

  /* --------------------------------------------------------------------- helpers ---- */
  function rel(ts) {
    if (!ts) return "never";
    var t = new Date(String(ts).replace(" ", "T"));
    if (isNaN(t)) return String(ts);
    var s = (Date.now() - t.getTime()) / 1000;
    if (s < 0) return "just now";
    if (s < 60) return Math.round(s) + "s ago";
    if (s < 3600) return Math.round(s / 60) + "m ago";
    if (s < 86400) return Math.round(s / 3600) + "h ago";
    return Math.round(s / 86400) + "d ago";
  }
  function dur(s) {
    s = Math.max(0, Math.round(s || 0));
    if (s < 60) return s + "s";
    if (s < 3600) return Math.round(s / 60) + "m";
    return (s / 3600).toFixed(1) + "h";
  }
  function sevIcon(sev) {
    return { critical: "◉", high: "▲", medium: "◆", low: "•", ok: "✓", info: "ℹ" }[sev] || "ℹ";
  }
  function providerOf(a) {
    var h = (a.host || "").toLowerCase();
    if (h.indexOf("gmail") >= 0 || /(^|@)gmail\./.test((a.username || "").toLowerCase())) return "gmail";
    if (h.indexOf("outlook") >= 0 || h.indexOf("office365") >= 0) return "outlook";
    if (h.indexOf("yahoo") >= 0) return "yahoo";
    return "imap";
  }
  function providerLabel(p) { return { gmail: "Gmail", outlook: "Outlook / Microsoft 365", yahoo: "Yahoo", imap: "IMAP" }[p] || "IMAP"; }

  /* ------------------------------------------------------------------ toasts ---- */
  function toast(n) {
    var host = document.getElementById("toast");
    if (!host) return;
    var el = document.createElement("div");
    el.className = "tst mt-toast sev-" + (n.severity || "info");
    el.innerHTML = '<i class="tic">' + sevIcon(n.severity) + '</i><div class="tbody"><b>' + C.esc(n.title) + '</b>' +
      (n.body ? '<span class="mini">' + C.esc(n.body) + '</span>' : '') +
      (n.account ? '<span class="mini mono">' + C.esc(n.account) + '</span>' : '') + '</div>' +
      '<span class="x" title="dismiss">✕</span><i class="tbar"></i>';
    el.querySelector(".x").onclick = function () { dismiss(); };
    if (n.case_id) el.onclick = function (e) { if (e.target.classList.contains("x")) return; location.hash = "#/case/" + n.case_id; dismiss(); };
    host.appendChild(el);
    requestAnimationFrame(function () { el.classList.add("on"); });
    var t1 = setTimeout(dismiss, 8000);
    function dismiss() {
      clearTimeout(t1);
      el.classList.remove("on"); el.classList.add("out");
      setTimeout(function () { el.remove(); }, 420);
    }
  }

  /* ------------------------------------------------------ notification centre ---- */
  function bell() {
    var b = document.getElementById("mt-bell");
    var side = document.querySelector(".side");
    if (!b && side) {
      b = document.createElement("button");
      b.id = "mt-bell"; b.className = "mt-bell"; b.title = "Notifications";
      b.innerHTML = '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" aria-hidden="true"><path d="M6 8a6 6 0 1112 0c0 4.2 1.4 5.6 2 6.2H4c.6-.6 2-2 2-6.2z" stroke="currentColor" stroke-width="1.6"/><path d="M9.5 18a2.5 2.5 0 005 0" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg><span class="mt-badge" id="mt-badge" hidden>0</span>';
      var brand = side.querySelector(".brand");
      side.insertBefore(b, brand ? brand.nextSibling : side.firstChild);
      b.onclick = togglePanel;
    }
    return b;
  }
  function panel() {
    var p = document.getElementById("mt-panel");
    if (!p) {
      p = document.createElement("div");
      p.id = "mt-panel"; p.className = "mt-panel";
      p.innerHTML = '<div class="mt-panel-h"><b>Notifications</b><span class="mini" id="mt-panel-sub"></span>' +
        '<span class="sp"></span><button class="btn sm" id="mt-read">Mark all read</button><button class="btn sm" id="mt-close">✕</button></div>' +
        '<div class="mt-panel-b" id="mt-panel-b"></div>';
      document.body.appendChild(p);
      p.querySelector("#mt-close").onclick = togglePanel;
      p.querySelector("#mt-read").onclick = function () { C.api("/api/notifications/read", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ all: true }) }).then(refresh).catch(function () {}); };
      var back = document.createElement("div");
      back.id = "mt-panel-back"; back.className = "mt-panel-back";
      back.onclick = togglePanel;
      document.body.appendChild(back);
    }
    return p;
  }
  function togglePanel() {
    state.open = !state.open;
    var p = panel(), back = document.getElementById("mt-panel-back");
    p.classList.toggle("on", state.open);
    if (back) back.classList.toggle("on", state.open);
    if (state.open) { refresh(); C.api("/api/notifications/read", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ all: true }) }).then(refresh).catch(function () {}); }
  }
  function refresh() {
    return C.api("/api/notifications?limit=60").then(function (d) {
      state.items = d.items || [];
      state.unread = d.unread || 0;
      state.unavailable = false;
      render();
    }).catch(function (e) {
      state.items = []; state.unread = 0;
      state.unavailable = /404|405|Not Found|Method Not Allowed/i.test(String(e && e.message)) ? "legacy" : "error";
      render();
    });
  }
  function render() {
    var badge = document.getElementById("mt-badge");
    if (badge) {
      badge.hidden = !state.unread;
      badge.textContent = state.unread > 99 ? "99+" : state.unread;
      if (state.unread) { badge.classList.remove("pop"); void badge.offsetWidth; badge.classList.add("pop"); }
    }
    var b = document.getElementById("mt-panel-b");
    if (!b) return;
    var sub = document.getElementById("mt-panel-sub");
    if (sub) sub.textContent = state.unread ? state.unread + " unread" : "all caught up";
    if (state.unavailable === "legacy") {
      b.innerHTML = '<div class="mt-empty"><div class="ico">ⓘ</div><b>Notification history needs the updated engine</b>' +
        '<span class="mini">This engine build has no notification endpoint. Start the updated engine with ' +
        '<code>python -m uvicorn main:app --host 0.0.0.0 --port 8000</code> from <code>_internal/backend</code> ' +
        'to get automatic mailbox monitoring, startup catch-up scans and detection history (see RUN.txt).</span></div>';
      return;
    }
    if (!state.items.length) {
      b.innerHTML = '<div class="mt-empty"><div class="ico">◍</div><b>No notifications yet</b><span class="mini">Detection events appear here when a monitored mailbox is scanned or a high-risk email is analysed.</span></div>';
      return;
    }
    b.innerHTML = state.items.map(function (n, i) {
      var counts = n.counts || {};
      var chips = [];
      if (counts.malicious) chips.push('<span class="chip bad">' + counts.malicious + ' malicious</span>');
      if (counts.suspicious) chips.push('<span class="chip warn">' + counts.suspicious + ' suspicious</span>');
      if (counts.clean) chips.push('<span class="chip ok">' + counts.clean + ' clean</span>');
      if (counts.score != null) chips.push('<span class="chip">risk ' + counts.score + '</span>');
      return '<div class="mt-n sev-' + (n.severity || "info") + (n.read ? "" : " unread") + '" data-id="' + C.esc(n.id) + '" data-case="' + C.esc(n.case_id || "") + '" style="--i:' + i + '">' +
        '<i class="ico">' + sevIcon(n.severity) + '</i>' +
        '<div class="bd"><b>' + C.esc(n.title) + '</b>' +
        (n.body ? '<span class="mini">' + C.esc(n.body) + '</span>' : '') +
        (chips.length ? '<div class="chip-row">' + chips.join("") + '</div>' : '') +
        '<span class="mini when">' + C.esc(rel(n.ts)) + (n.account ? ' · ' + C.esc(n.account) : '') + '</span></div></div>';
    }).join("");
    b.querySelectorAll(".mt-n").forEach(function (el) {
      el.onclick = function () {
        var id = el.dataset.id, cid = el.dataset.case;
        C.api("/api/notifications/read", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: id }) }).catch(function () {});
        if (cid) { togglePanel(); location.hash = "#/case/" + cid; }
        else refresh();
      };
    });
  }

  /* ------------------------------------------------------------- modal dialog ---- */
  function confirm(opts) {
    opts = opts || {};
    return new Promise(function (res) {
      var back = document.createElement("div"); back.className = "mt-modal-back";
      var box = document.createElement("div"); box.className = "mt-modal" + (opts.danger ? " danger" : "");
      box.innerHTML = '<h3>' + C.esc(opts.title || "Please confirm") + '</h3><div class="mb">' + (opts.body || "") + '</div>' +
        '<div class="mf"><button class="btn" data-no>' + C.esc(opts.cancel || "Cancel") + '</button>' +
        '<button class="btn ' + (opts.danger ? "danger" : "p") + '" data-yes>' + C.esc(opts.ok || "Confirm") + '</button></div>';
      document.body.appendChild(back); document.body.appendChild(box);
      requestAnimationFrame(function () { back.classList.add("on"); box.classList.add("on"); });
      function done(v) {
        back.classList.remove("on"); box.classList.remove("on");
        setTimeout(function () { back.remove(); box.remove(); }, 300);
        res(v);
      }
      box.querySelector("[data-no]").onclick = function () { done(false); };
      box.querySelector("[data-yes]").onclick = function () { done(true); };
      back.onclick = function () { done(false); };
      document.addEventListener("keydown", function esc(e) {
        if (e.key === "Escape") { document.removeEventListener("keydown", esc); done(false); }
      });
      box.querySelector("[data-yes]").focus();
    });
  }

  /* ------------------------------------------------------- background / minimise ---- */
  function backgroundControl() {
    var foot = document.querySelector(".side-foot");
    if (!foot || document.getElementById("mt-bg-btn")) return;
    var b = document.createElement("button");
    b.id = "mt-bg-btn"; b.className = "btn sm mt-bg-btn"; b.textContent = "⤓ Run in background";
    b.title = "Hide the window — monitoring and scanning continue in the server process";
    b.onclick = function () {
      var api = w.pywebview && w.pywebview.api;
      try {
        if (api && typeof api.hide === "function") { api.hide(); return; }
        if (api && typeof api.minimize === "function") { api.minimize(); return; }
      } catch (e) {}
      C.toast("Monitoring keeps running", "Minimise or hide this window — the MailTrace AI service keeps scanning the selected accounts and will notify you when new mail is analysed.");
    };
    foot.insertBefore(b, foot.firstChild);
  }

  /* --------------------------------------------------------------- accounts page ---- */
  function card(a) {
    var p = providerOf(a);
    var selected = a.selected;
    var status = a.last_error ? "error" : (a.active_job ? "scanning" : (selected ? "selected" : "paused"));
    var statusText = { error: "Connection problem", scanning: "Scanning now", selected: "Monitoring", paused: "Not monitored" }[status];
    var job = (state.monitor && state.monitor.active_jobs || []).find(function (j) { return j.id === a.active_job; });
    var prog = job && job.total ? Math.round((job.analysed + job.duplicates + job.errors) / job.total * 100) : 0;
    var cp = Object.keys(a.checkpoints || {}).map(function (f) { return C.esc(f) + " #" + a.checkpoints[f]; }).join(" · ");
    return '<div class="acct sev-' + status + '" data-id="' + C.esc(a.id) + '">' +
      '<div class="acct-h">' +
        '<div class="prov ' + p + '">' + (p === "gmail" ? "G" : p === "outlook" ? "O" : p === "yahoo" ? "Y" : "✉") + '</div>' +
        '<div class="who"><b>' + C.esc(a.name || a.username || "Mailbox") + '</b>' +
          '<span class="mini mono">' + C.esc(a.username || "") + '</span></div>' +
        '<span class="pill ' + status + '"><i></i>' + statusText + '</span>' +
      '</div>' +
      '<div class="acct-g">' +
        '<div><label>Status</label><b>' + (a.has_secret ? "Connected" : "No credentials stored") + ' · ' + providerLabel(p) + '</b></div>' +
        '<div><label>Server</label><b class="mono">' + C.esc(a.host || "—") + ":" + C.esc(a.port || "—") + '</b></div>' +
        '<div><label>Folders</label><b class="mono">' + C.esc((a.folders || []).join(", ") || "INBOX") + '</b></div>' +
        '<div><label>Last checked</label><b>' + C.esc(a.last_run ? rel(a.last_run) : "never") + '</b></div>' +
        '<div><label>Next check</label><b>' + C.esc(selected ? (a.mode === "idle" ? "on server push" : "in " + dur(a.due_in_s)) : "—") + '</b></div>' +
        '<div><label>Checkpoint</label><b class="mono">' + (cp || "none yet (first scan is a backfill)") + '</b></div>' +
      '</div>' +
      (job ? '<div class="acct-job"><div class="row-between"><span class="mini">Scanning — ' + job.analysed + '/' + job.total + ' analysed' + (job.malicious ? ' · <b style="color:var(--crit)">' + job.malicious + ' malicious</b>' : '') + '</span><span class="mini mono">' + (job.phase || job.status) + '</span></div><div class="pb"><i style="width:' + prog + '%"></i></div></div>' : '') +
      (a.last_error ? '<div class="acct-err"><b>Last error</b><span class="mini">' + C.esc(a.last_error) + '</span></div>' : '') +
      '<div class="acct-a">' +
        '<label class="sw"><input type="checkbox" data-act="select" ' + (selected ? "checked" : "") + '><span></span>Monitor this account</label>' +
        '<select data-act="mode">' +
          '<option value="idle" ' + (a.mode === "idle" ? "selected" : "") + '>Push (IMAP IDLE)</option>' +
          '<option value="monitor" ' + (a.mode === "monitor" ? "selected" : "") + '>Poll every interval</option>' +
          '<option value="once" ' + (a.mode === "once" ? "selected" : "") + '>Manual only</option>' +
        '</select>' +
        '<input type="number" min="1" max="720" value="' + (a.interval_min || 5) + '" data-act="interval" title="poll interval in minutes" style="width:74px">' +
        '<button class="btn sm" data-act="scan">Scan now</button>' +
        '<button class="btn sm" data-act="test">Test</button>' +
        '<button class="btn sm danger" data-act="remove">Disconnect</button>' +
      '</div></div>';
  }

  function accounts() {
    var view = C.view;
    var sk = w.MTmotion ? w.MTmotion.skeleton : function (n) { return new Array(n || 3).fill('<div class="skel"></div>').join(""); };
    view.innerHTML = '<div class="page-head"><div><div class="eyebrow">Automatic mailbox monitoring</div><h1>Mail Accounts</h1>' +
      '<div class="sub" style="margin:0">loading monitoring state…</div></div></div>' +
      '<div class="grid g3"><div class="card">' + sk(4) + '</div><div class="card">' + sk(4) + '</div></div>';
    return C.api("/api/monitor").then(function (mon) {
      state.monitor = mon;
      render_accounts(mon);
    }).catch(function (e) {
      var legacy = /404|405|Not Found|Method Not Allowed/i.test(String(e && e.message));
      view.innerHTML = '<div class="page-head"><div><div class="eyebrow">Automatic mailbox monitoring</div><h1>Mail Accounts</h1></div></div>' +
        (legacy
          ? '<div class="card err-state"><b>This engine build has no mailbox-monitoring API</b>' +
            '<span class="mini">The window you are using is served by an older engine build (v1.2.0). Mail-account monitoring, ' +
            'the startup catch-up scan and notification history were added in engine v1.3.0.</span>' +
            '<div class="mini" style="margin-top:6px"><b>To use them:</b> open a terminal in ' +
            '<code>MAILWORKING\\MailTrace AI\\_internal\\backend</code> and run' +
            '<pre style="margin:6px 0">python -m uvicorn main:app --host 0.0.0.0 --port 8000</pre>' +
            'then open <code>http://localhost:8000</code> in your browser. Everything else in this build ' +
            '(analysis, 3D globe, snake, forensic graph, reports) works as-is.</div>' +
            '<button class="btn" id="acc-retry">Retry</button></div>'
          : '<div class="card err-state"><b>Could not load monitoring state</b><span class="mini">' + C.esc(e.message) + '</span><button class="btn" id="acc-retry">Retry</button></div>');
      var r = document.getElementById("acc-retry"); if (r) r.onclick = C.routes.accounts;
    });
  }

  function render_accounts(mon) {
    var view = C.view;
    var sel = (mon.sources || []).filter(function (a) { return a.selected; }).length;
    var err = (mon.sources || []).filter(function (a) { return a.last_error; }).length;
    view.innerHTML =
      '<div class="page-head" data-reveal><div><div class="eyebrow">Automatic mailbox monitoring</div><h1>Mail Accounts</h1>' +
      '<div class="sub" style="margin:0">' + mon.accounts + ' account(s) connected · <b>' + sel + '</b> selected for monitoring' +
      (err ? ' · <b style="color:var(--crit)">' + err + ' with errors</b>' : '') +
      ' · monitor ' + (mon.enabled ? '<b style="color:var(--green)">running</b>' : '<b style="color:var(--amber)">paused</b>') +
      (mon.last_catchup ? ' · startup catch-up ' + C.esc(rel(mon.last_catchup)) : '') + '</div></div>' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
      '<button class="btn p" id="acc-scan">⇊ Scan selected now</button>' +
      '<button class="btn" id="acc-toggle">' + (mon.enabled ? "⏸ Pause monitoring" : "▶ Resume monitoring") + '</button>' +
      '</div></div>' +

      '<div class="card mon-bar" data-reveal>' +
        '<div class="mon-dot ' + (mon.enabled ? "on" : "") + '"></div>' +
        '<div><b>Background monitoring ' + (mon.enabled ? "active" : "paused") + '</b>' +
        '<span class="mini">Started ' + C.esc(mon.started_at ? rel(mon.started_at) : "—") + ' · last scheduler tick ' + C.esc(mon.last_tick ? rel(mon.last_tick) : "—") +
        ' · ' + (mon.idle_watchers || []).length + ' push connection(s) · ' + (mon.active_jobs || []).length + ' scan(s) running</span></div>' +
        '<div class="sp"></div>' +
        '<span class="mini mono">mail is fetched read-only; nothing is deleted or marked as read on the server</span>' +
      '</div>' +

      ((mon.sources || []).length
        ? '<div class="grid g2" id="acc-grid">' + mon.sources.map(card).join("") + '</div>'
        : '<div class="card empty-state" data-reveal><div class="ico">✉</div><b>No mail account connected</b>' +
          '<span class="mini">Connect a Gmail account with an App Password to let MailTrace AI scan new mail automatically. ' +
          'Mail that arrives while the app is closed is picked up by the startup catch-up scan.</span></div>') +

      '<div class="card" data-reveal><div class="hd"><h2 style="margin:0">Connect an account</h2><span class="mini">credentials are stored locally, obfuscated, and never sent anywhere except the mail server</span></div>' +
      '<div class="prov-row">' +
        '<button class="prov-chip on" data-p="gmail">Gmail</button>' +
        '<button class="prov-chip" data-p="outlook">Outlook / Microsoft 365</button>' +
        '<button class="prov-chip" data-p="imap">Other IMAP</button>' +
      '</div>' +
      '<div class="grid g2" style="margin-top:12px">' +
        '<div><label class="lbl">Email address</label><input id="ac-mail" placeholder="you@gmail.com" autocomplete="off"></div>' +
        '<div><label class="lbl">App password <span class="mini">Gmail → Security → App passwords (16 chars)</span></label><input id="ac-pass" type="password" placeholder="• • • • • • • • • • • • • • • •" autocomplete="new-password"></div>' +
        '<div><label class="lbl">IMAP host</label><input id="ac-host" value="imap.gmail.com"></div>' +
        '<div><label class="lbl">Port</label><input id="ac-port" type="number" value="993"></div>' +
        '<div><label class="lbl">Folders <span class="mini">comma separated</span></label><input id="ac-folders" value="INBOX"></div>' +
        '<div><label class="lbl">Monitoring</label><select id="ac-mode"><option value="idle" selected>Push (IMAP IDLE — instant)</option><option value="monitor">Poll every interval</option><option value="once">Manual only</option></select></div>' +
      '</div>' +
      '<div style="display:flex;gap:8px;margin-top:12px;align-items:center;flex-wrap:wrap">' +
        '<button class="btn p" id="ac-connect">⚡ Connect &amp; start monitoring</button>' +
        '<button class="btn" id="ac-test">Test connection</button>' +
        '<label class="lbl" style="display:flex;gap:6px;align-items:center;margin:0"><input type="checkbox" id="ac-backfill" checked> scan messages from</label>' +
        '<input type="date" id="ac-since" style="width:auto">' +
      '</div>' +
      '<div id="ac-out" class="mini" style="margin-top:10px"></div></div>';

    /* ------------------------------------------------------------- bindings ---- */
    var out = function (msg, bad) {
      var o = document.getElementById("ac-out");
      if (o) { o.innerHTML = msg; o.className = "mini" + (bad ? " err" : " ok"); }
    };
    var prov = "gmail";
    view.querySelectorAll(".prov-chip").forEach(function (b) {
      b.onclick = function () {
        prov = b.dataset.p;
        view.querySelectorAll(".prov-chip").forEach(function (x) { x.classList.toggle("on", x === b); });
        var preset = { gmail: ["imap.gmail.com", 993], outlook: ["outlook.office365.com", 993], imap: ["", 993] }[prov];
        document.getElementById("ac-host").value = preset[0];
        document.getElementById("ac-port").value = preset[1];
      };
    });
    var form = function () {
      return {
        name: (document.getElementById("ac-mail").value.trim() || "Mailbox") + (prov === "gmail" ? " — Gmail" : ""),
        kind: "imap",
        host: document.getElementById("ac-host").value.trim(),
        port: parseInt(document.getElementById("ac-port").value) || 993,
        username: document.getElementById("ac-mail").value.trim(),
        secret: document.getElementById("ac-pass").value,
        folders: document.getElementById("ac-folders").value.split(",").map(function (s) { return s.trim(); }).filter(Boolean),
        mode: document.getElementById("ac-mode").value,
        interval_min: 10,
        enabled: true,
        since: document.getElementById("ac-since").value || null,
        auth: "password",
        authorization: "account owner consent (configured in MailTrace AI)"
      };
    };
    var testBtn = document.getElementById("ac-test");
    testBtn.onclick = function () {
      var f = form();
      if (!f.host || !f.username || !f.secret) { out("Host, email and app password are required.", true); return; }
      testBtn.disabled = true; testBtn.textContent = "Testing…";
      out('<span class="spin sm"></span> connecting to ' + C.esc(f.host) + "…");
      C.api("/api/sources/test", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(f) })
        .then(function (r) {
          testBtn.disabled = false; testBtn.textContent = "Test connection";
          if (r.ok) out("✓ Connected to <b>" + C.esc(f.host) + "</b> in " + r.ms + " ms · " + (r.folders || []).length + " folders · " + (r.count != null ? r.count + " message(s) in INBOX" + (r.since ? " since " + C.esc(r.since) : "") : ""));
          else out("✕ " + C.esc(r.error || "connection failed"), true);
        })
        .catch(function (e) { testBtn.disabled = false; testBtn.textContent = "Test connection"; out("✕ " + C.esc(e.message), true); });
    };
    document.getElementById("ac-connect").onclick = function () {
      var b = this, f = form();
      if (!f.host || !f.username || !f.secret) { out("Host, email and app password are required.", true); return; }
      b.disabled = true; b.textContent = "Connecting…";
      C.api("/api/sources", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(f) })
        .then(function () { C.toast("Account connected", f.username + " · monitoring " + f.mode); accounts(); })
        .catch(function (e) { b.disabled = false; b.textContent = "⚡ Connect & start monitoring"; out("✕ " + C.esc(e.message), true); });
    };
    document.getElementById("acc-scan").onclick = function () {
      var b = this; b.disabled = true; b.textContent = "Scanning…";
      C.api("/api/monitor/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode: "incremental" }) })
        .then(function (r) {
          b.disabled = false; b.textContent = "⇊ Scan selected now";
          var err = (r.jobs || []).filter(function (j) { return j.error; });
          C.toast(err.length ? "Scan could not start" : "Scan started",
            err.length ? err[0].error : (r.jobs || []).length + " account(s) · new mail only (checkpoint applied)", !!err.length);
          setTimeout(accounts, 1200);
        })
        .catch(function (e) { b.disabled = false; b.textContent = "⇊ Scan selected now"; C.toast("Scan failed", e.message, true); });
    };
    document.getElementById("acc-toggle").onclick = function () {
      var want = !(state.monitor && state.monitor.enabled);
      C.api("/api/monitor/enable?enabled=" + (want ? "true" : "false"), { method: "POST" })
        .then(accounts).catch(function (e) { C.toast("Could not update monitor", e.message, true); });
    };

    view.querySelectorAll(".acct").forEach(function (el) {
      var id = el.dataset.id;
      var put = function (body) {
        return C.api("/api/sources/" + id, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      };
      el.querySelector('[data-act="select"]').onchange = function (e) {
        var on = e.target.checked;
        put({ enabled: on, mode: on ? (el.querySelector('[data-act="mode"]').value === "once" ? "monitor" : el.querySelector('[data-act="mode"]').value) : "once" })
          .then(accounts).catch(function (err) { C.toast("Could not update account", err.message, true); });
      };
      el.querySelector('[data-act="mode"]').onchange = function (e) {
        put({ mode: e.target.value, enabled: e.target.value !== "once" }).then(accounts).catch(function (err) { C.toast("Could not update account", err.message, true); });
      };
      el.querySelector('[data-act="interval"]').onchange = function (e) {
        put({ interval_min: Math.max(1, parseInt(e.target.value) || 5) }).then(accounts).catch(function () {});
      };
      el.querySelector('[data-act="scan"]').onclick = function () {
        var b = this; b.disabled = true; b.textContent = "…";
        C.api("/api/sources/" + id + "/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode: "incremental" }) })
          .then(function (r) {
            var j = (r.jobs || [])[0];
            C.toast(j && j.error ? "Scan could not start" : "Scan started", j && j.error ? j.error : "fetching new mail since the last checkpoint", !!(j && j.error));
            setTimeout(accounts, 1500);
          }).catch(function (err) { C.toast("Scan failed", err.message, true); b.disabled = false; b.textContent = "Scan now"; });
      };
      el.querySelector('[data-act="test"]').onclick = function () {
        var b = this, a = (state.monitor.sources || []).find(function (x) { return x.id === id; });
        b.disabled = true; b.textContent = "…";
        C.api("/api/sources/" + id, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}) })
          .then(function () {
            return C.api("/api/sources/test?sid=" + id, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ host: a.host, port: a.port, username: a.username }) });
          })
          .then(function (r) {
            b.disabled = false; b.textContent = "Test";
            C.toast(r.ok ? "Connection OK" : "Connection failed", r.ok ? a.host + " responded in " + r.ms + " ms" : (r.error || "unknown error"), !r.ok);
            if (r.ok) put({ last_error: null }).then(accounts).catch(function () {});
            else accounts();
          }).catch(function (e) { b.disabled = false; b.textContent = "Test"; C.toast("Connection failed", e.message, true); });
      };
      el.querySelector('[data-act="remove"]').onclick = function () {
        var a = (state.monitor.sources || []).find(function (x) { return x.id === id; });
        confirm({
          title: "Disconnect " + (a && a.username ? a.username : "account") + "?",
          body: "<p class='mini'>MailTrace AI stops monitoring this mailbox and deletes the stored credentials. " +
                "Cases already analysed stay in the evidence store.</p>",
          ok: "Disconnect", danger: true
        }).then(function (yes) {
          if (!yes) return;
          C.api("/api/sources/" + id, { method: "DELETE" }).then(function () { C.toast("Account disconnected", (a && a.username) || id); accounts(); })
            .catch(function (e) { C.toast("Could not disconnect", e.message, true); });
        });
      };
    });

    if (w.MTfx) w.MTfx.reveal(view);
    startPoll();
  }

  function startPoll() {
    stopPoll();
    // live status while the page is open (job progress, last-checked, errors)
    state.poll = setInterval(function () {
      if (!/^#\/accounts/.test(location.hash)) return stopPoll();
      C.api("/api/monitor").then(function (mon) {
        state.monitor = mon;
        var grid = document.getElementById("acc-grid");
        if (grid) grid.innerHTML = (mon.sources || []).map(card).join("");
        bindGrid();
        var bar = document.querySelector(".mon-bar .mini");
        if (bar) bar.textContent = "Started " + rel(mon.started_at) + " · last scheduler tick " + rel(mon.last_tick) +
          " · " + (mon.idle_watchers || []).length + " push connection(s) · " + (mon.active_jobs || []).length + " scan(s) running";
      }).catch(function () {});
    }, 4000);
  }
  function stopPoll() { if (state.poll) clearInterval(state.poll); state.poll = 0; }

  function bindGrid() {
    var grid = document.getElementById("acc-grid");
    if (!grid) return;
    // re-created markup: re-run the action bindings without rebuilding the whole page
    var ev = new Event("mt-rebind");
    grid.querySelectorAll(".acct").forEach(function (el) {
      if (el.dataset.bound) return;
      el.dataset.bound = "1";
      el.querySelectorAll("[data-act]").forEach(function (b) {
        b.onclick = null; b.onchange = null;
      });
    });
    void ev;
  }

  /* ------------------------------------------------------------------- public ---- */
  w.MTConsole = {
    bind: function (ctx) {
      C = ctx;
      bell(); panel(); refresh();
      backgroundControl();
      setInterval(refresh, 30000);
    },
    onEvent: function (payload, type) {
      if (!payload) return;
      if (type === "notify") {
        state.unread = (state.unread || 0) + 1;
        toast(payload.notification || payload);
        refresh();
        // desktop notification when the shell supports it (pywebview bridge or web Notifications)
        try {
          var n = payload.notification || {};
          if (w.pywebview && w.pywebview.api && typeof w.pywebview.api.notify === "function") w.pywebview.api.notify(n.title, n.body || "");
          else if (w.Notification && Notification.permission === "granted") new Notification(n.title, { body: n.body || "", silent: true });
        } catch (e) {}
      } else if (type === "job-done" && payload.job && payload.job.kind === "imap") {
        refresh();
        if (/^#\/accounts/.test(location.hash)) accounts();
      }
    },
    accounts: accounts,
    confirm: confirm,
    toast: toast,
    refresh: refresh,
    state: state
  };
})();
