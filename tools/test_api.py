#!/usr/bin/env python3
"""MailTrace AI — backend regression smoke test against a live server.
Verifies the real analysis path still works after the frontend/motion work:
ingestion, streaming pipeline, geolocation honesty, campaigns, graph, reports."""
import json, sys, time, urllib.request, urllib.parse

BASE = "http://127.0.0.1:8000"
P = F = 0


def ok(name, cond, extra=""):
    global P, F
    if cond:
        P += 1
        print("  ✓ " + name)
    else:
        F += 1
        print("  ✗ " + name + ((" — " + str(extra)) if extra else ""))


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=60) as r:
        ct = r.headers.get("content-type", "")
        body = r.read()
        return (json.loads(body) if "json" in ct else body), r.status


def put(path, data=None, ctype="application/json"):
    body = data if isinstance(data, bytes) else json.dumps(data or {}).encode()
    req = urllib.request.Request(BASE + path, data=body, method="PUT")
    req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read()
        return (json.loads(raw) if raw[:1] in (b"{", b"[") else raw), r.status


def post(path, data=None, ctype=None):
    body = data if isinstance(data, bytes) else urllib.parse.urlencode(data or {}).encode()
    req = urllib.request.Request(BASE + path, data=body, method="POST")
    if ctype:
        req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req, timeout=180) as r:
        raw = r.read()
        return (json.loads(raw) if raw[:1] in (b"{", b"[") else raw), r.status


print("[1] service")
h, _ = get("/api/health")
ok("health responds", isinstance(h, dict) and "version" in h, h)
ok("engine version 1.3.0", h.get("version") == "1.3.0", h.get("version"))
ok("NLP model loaded", bool((h.get("model") or {}).get("model")), h.get("model"))

print("\n[2] real data endpoints")
st, _ = get("/api/stats")
ok("stats has analysed emails", st.get("total", 0) >= 1, st.get("total"))
cases, _ = get("/api/cases?limit=5")
ok("cases listed", len(cases) >= 1, len(cases))
camps, _ = get("/api/campaigns")
ok("campaign clustering returns a list", isinstance(camps, list), type(camps))
hot, _ = get("/api/geo/hotspots")
ok("geo hotspots have points", len(hot.get("points", [])) >= 1, len(hot.get("points", [])))
pts = hot.get("points", [])
ok("every point carries a precision label", all(p.get("precision") for p in pts),
   [p.get("precision") for p in pts][:5])
ok("no invented coordinates: lat/lon present or point flagged approximate",
   all((p.get("lat") is not None and p.get("lon") is not None) or p.get("approximate") for p in pts))
ok("country-level points are labelled country",
   all(p["precision"] == "country" for p in pts if p.get("approximate") and p.get("precision")),
   [p["precision"] for p in pts if p.get("approximate")])
g, _ = get("/api/graph")
ok("link-analysis graph has nodes and edges", len(g.get("nodes", [])) > 0 and len(g.get("edges", [])) > 0,
   (len(g.get("nodes", [])), len(g.get("edges", []))))
lk, _ = get("/api/lookup/ip/5.188.206.14")
ok("IP lookup returns real enrichment", bool(lk.get("country")) and lk.get("lat") is not None, str(lk)[:120])

print("\n[3] streaming analysis pipeline (real backend stages)")
RAW = b"""Return-Path: <billing@secure-paypa1-update.example>
Received: from mail.secure-paypa1-update.example (unknown [5.188.206.14]) by mx.aicte-india.org with SMTP; Tue, 16 Sep 2026 11:02:11 +0530
Received: from mx.aicte-india.org (mx.aicte-india.org [103.21.58.9]) by internal.corp.local with ESMTPS; Tue, 16 Sep 2026 11:02:14 +0530
From: "PayPal Security" <billing@secure-paypa1-update.example>
Reply-To: paypal.helpdesk.review@gmail.com
To: <registrar@aicte-india.org>
Subject: URGENT: Your account will be suspended in 24 hours
Date: Tue, 16 Sep 2026 11:02:11 +0530
Message-ID: <9f2c1a7b0001@secure-paypa1-update.example>
Content-Type: text/html

<html><body><p>Dear customer, verify your account now to avoid suspension.</p>
<a href="http://secure-paypa1-update.example/login">Verify account</a></body></html>
"""
req = urllib.request.Request(
    BASE + "/api/analyze/stream",
    data=b"--x\r\nContent-Disposition: form-data; name=\"raw_text\"\r\n\r\n" + RAW +
         b"\r\n--x\r\nContent-Disposition: form-data; name=\"persist\"\r\n\r\nfalse\r\n--x--\r\n",
    method="POST")
req.add_header("Content-Type", "multipart/form-data; boundary=x")
stages, result, err = [], None, None
with urllib.request.urlopen(req, timeout=180) as r:
    for line in r:
        line = line.strip()
        if not line:
            continue
        ev = json.loads(line)
        if ev.get("type") == "stage":
            stages.append((ev.get("id"), ev.get("status")))
        elif ev.get("type") == "result":
            result = ev.get("result")
        elif ev.get("type") == "error":
            err = ev.get("message")
ok("stream emitted stage events", len(stages) >= 5, stages[:6])
ok("stages reach 'done'", any(s[1] == "done" for s in stages), stages)
ok("stream returned a result", result is not None, err)
if result:
    sc = result.get("score", {})
    ok("real risk score produced", isinstance(sc.get("score"), (int, float)), sc)
    ok("verdict produced", sc.get("verdict") in
       ("malicious", "likely_malicious", "suspicious", "low_risk", "clean"), sc.get("verdict"))
    og = result.get("attribution", {}).get("origin_geo", {})
    ok("geolocation returned country-level data", bool(og.get("country")), og.get("country"))
    ok("trace path reconstructed", len(result.get("trace_path", [])) >= 1,
       len(result.get("trace_path", [])))
    ok("header auth evaluated", result.get("headers", {}).get("auth", {}).get("spf") is not None)

print("\n[4] saved case: report + evidence")
cid = cases[0]["id"]
pdf, _ = get("/api/cases/%s/report.pdf" % cid)
ok("PDF report generated", pdf[:4] == b"%PDF", pdf[:8])
js, _ = get("/api/cases/%s/report.json" % cid)
ok("JSON report generated", isinstance(js, dict) and js.get("id") == cid, list(js)[:4] if isinstance(js, dict) else js[:80])
det, _ = get("/api/cases/%s" % cid)
ok("case detail loaded", isinstance(det, dict) and det.get("id") == cid, list(det)[:5] if isinstance(det, dict) else det)
ok("chain of custody recorded", isinstance(det.get("custody", []), list), det.get("custody"))

print("\n[5] notifications (real events only)")
nt, _ = get("/api/notifications?limit=100")
items = nt["items"]
ok("notification history stored", len(items) > 0, len(items))
ok("unread counter matches list", nt["unread"] == len([i for i in items if not i["read"]]), nt["unread"])
threats = [n for n in items if n["kind"] == "threat"]
ok("threat notifications carry a case id", all(n["case_id"] for n in threats))
bad = []
for n in threats:
    d0, _ = get("/api/cases/%s" % n["case_id"])
    if d0.get("verdict") not in ("malicious", "likely_malicious"):
        bad.append((n["case_id"], d0.get("verdict")))
ok("every threat notification maps to a real high-risk case", not bad, bad[:3])
ok("threat notifications are at least the current high-risk cases",
   len(threats) >= st["by_verdict"].get("malicious", 0) + st["by_verdict"].get("likely_malicious", 0),
   len(threats))
if threats:
    det, _ = get("/api/cases/%s" % threats[0]["case_id"])
    ok("notification links to a real case", isinstance(det, dict) and det.get("id") == threats[0]["case_id"])
    ok("severity is one of the known levels",
       threats[0]["severity"] in ("critical", "high", "medium", "low", "ok"), threats[0]["severity"])
rd, _ = post("/api/notifications/read", json.dumps({"all": True}).encode(), "application/json")
ok("mark all read", rd.get("unread") == 0, rd)

print("\n[6] background monitoring + account selection")
mon, _ = get("/api/monitor")
ok("background monitor is running", mon.get("running") is True, mon.get("running"))
ok("monitor reports account list", isinstance(mon.get("sources"), list))
src, _ = post("/api/sources", json.dumps({
    "name": "Gmail — test", "kind": "imap", "host": "imap.gmail.com", "port": 993,
    "username": "mailtrace.test@example.com", "secret": "not-a-real-app-password",
    "folders": ["INBOX"], "mode": "monitor", "interval_min": 15, "enabled": True,
    "authorization": "test consent"}).encode(), "application/json")
sid = src["id"]
ok("account created", bool(sid), src)
ok("secret is never returned by the API", "secret" not in src and src.get("has_secret") is True)
acc, _ = get("/api/accounts")
mine = [a for a in acc["accounts"] if a["id"] == sid]
ok("account appears in /api/accounts", len(mine) == 1)
ok("account is selected for monitoring", bool(mine) and mine[0]["selected"] is True, mine and mine[0])
ok("monitoring mode stored", bool(mine) and mine[0]["mode"] == "monitor", mine and mine[0]["mode"])
put("/api/sources/" + sid, {"enabled": False})
acc2, _ = get("/api/accounts")
mine2 = [a for a in acc2["accounts"] if a["id"] == sid][0]
ok("deselecting an account persists", mine2["selected"] is False, mine2["selected"])
put("/api/sources/" + sid, {"enabled": True, "mode": "monitor"})
acc3, _ = get("/api/accounts")
ok("re-selecting an account persists", [a for a in acc3["accounts"] if a["id"] == sid][0]["selected"] is True)

tst, _ = post("/api/sources/test", json.dumps({"host": "imap.gmail.com", "port": 993,
                                               "username": "nobody@example.com", "secret": "x"}).encode(),
              "application/json")
ok("connection failure is reported, not crashed", tst.get("ok") is False and bool(tst.get("error")), tst)
ok("connection failure has a readable message", isinstance(tst.get("error"), str) and len(tst["error"]) > 8, tst.get("error"))
sc, _ = post("/api/monitor/scan", json.dumps({"mode": "incremental"}).encode(), "application/json")
ok("scan-now accepts the request", isinstance(sc.get("jobs"), list), sc)
time.sleep(12)
mon2, _ = get("/api/monitor")
mine3 = [a for a in mon2["sources"] if a["id"] == sid][0]
ok("failed scan records a real error on the account", bool(mine3.get("last_error")), mine3.get("last_error"))
errn = [n for n in get("/api/notifications?limit=100")[0]["items"] if n["kind"] == "error"]
ok("failed scan produced a notification", len(errn) >= 1, len(errn))
ok("checkpoint stays empty while nothing was fetched (no fake progress)",
   isinstance(mine3.get("checkpoints"), dict) and mine3["checkpoints"] == {}, mine3.get("checkpoints"))
off, _ = post("/api/monitor/enable?enabled=false")
ok("monitor can be paused", off.get("enabled") is False, off)
on, _ = post("/api/monitor/enable?enabled=true")
ok("monitor can be resumed", on.get("enabled") is True, on)
req = urllib.request.Request(BASE + "/api/sources/" + sid, method="DELETE")
with urllib.request.urlopen(req, timeout=60) as r:
    ok("account removed", r.status == 200)
acc4, _ = get("/api/accounts")
ok("removed account is gone", not [a for a in acc4["accounts"] if a["id"] == sid])

print("\n%s %d/%d" % ("PASS" if F == 0 else "FAIL", P, P + F))
sys.exit(1 if F else 0)
