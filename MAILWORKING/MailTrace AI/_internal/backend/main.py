"""
MailTrace AI — API server.
FastAPI backend serving the analysis engine, case store, campaign clustering, PDF reports and the analyst SPA.
"""
import os, sys, io, json, time, glob, asyncio, threading, hashlib, logging
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, BackgroundTasks, Header
from fastapi.responses import JSONResponse, Response, FileResponse, HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyzer.engine import analyze_email
from analyzer import intel, content as content_mod
from analyzer.common import load_org_profile, save_org_profile, load_settings, save_settings, DATA_DIR
import store, report, ingest

ROOT = os.path.dirname(os.path.abspath(__file__))
FRONTEND = os.path.join(os.path.dirname(ROOT), "frontend")
SAMPLES = os.path.join(ROOT, "samples")

app = FastAPI(title="MailTrace AI", version="1.2.0", description="AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ---- live alert stream (SSE) ----
_subscribers: List[asyncio.Queue] = []
_loop: Optional[asyncio.AbstractEventLoop] = None

def _publish(evt: Dict[str, Any]):
    if _loop is None: return
    for q in list(_subscribers):
        try: _loop.call_soon_threadsafe(q.put_nowait, evt)
        except Exception: pass

@app.on_event("startup")
async def _startup():
    global _loop
    _loop = asyncio.get_event_loop()
    content_mod.load_model()
    st = content_mod.model_status()
    logging.getLogger("uvicorn.error").info("MailTrace AI: NLP model %s (%s)", "loaded" if st["loaded"] else "NOT LOADED - " + str(st["error"]), st["backend"])
    logging.getLogger("uvicorn.error").info("MailTrace AI: %d cases in store, %s", store.count_cases(), "OFFLINE mode" if intel.OFFLINE else "live enrichment enabled")
    threading.Thread(target=intel.refresh_tor, daemon=True).start()
    ingest.set_publisher(_publish)
    ingest.start_monitor()                        # polls / IDLEs the configured mailboxes in the background

def _actor(x_analyst: Optional[str]) -> str:
    return (x_analyst or "analyst").strip()[:60]

def _run(raw: bytes, filename: str, actor: str, source: str = "upload", persist: bool = True) -> Dict[str, Any]:
    org = load_org_profile()
    result = analyze_email(raw, org)
    if persist:
        meta = store.save_case(result, raw, filename, actor=actor, source=source)
        result["case_id"] = meta["case_id"]; result["campaign_id"] = meta["campaign_id"]
        if result["score"]["score"] >= 60:
            _publish({"type": "alert", "case_id": result["id"], "score": result["score"]["score"], "label": result["score"]["label"], "subject": result["headers"]["subject"],
                      "sender": result["headers"]["from"]["address"], "threat": result["threat"]["primary"], "origin": (result["attribution"].get("origin_geo") or {}).get("country"), "ts": time.time()})
        else:
            _publish({"type": "case", "case_id": result["id"], "score": result["score"]["score"], "label": result["score"]["label"], "subject": result["headers"]["subject"], "ts": time.time()})
    intel.flush_cache()
    return result

# ------------------------------------------------------------------ API ----
@app.get("/api/health")
def health():
    return {"ok": True, "offline": intel.OFFLINE, "model": content_mod.model_meta(), "model_status": content_mod.model_status(),
            "org": load_org_profile().get("organization"), "time": time.time(), "python": sys.version.split()[0], "platform": sys.platform,
            "desktop": os.environ.get("MAILTRACE_DESKTOP") == "1", "data_dir": DATA_DIR, "version": app.version, "ingest": ingest.status()}

@app.post("/api/analyze")
async def analyze(file: UploadFile = File(None), raw_text: str = Form(None), persist: bool = Form(True), x_analyst: Optional[str] = Header(None)):
    if file is not None:
        raw = await file.read(); name = file.filename or "upload.eml"
    elif raw_text:
        raw = raw_text.encode("utf-8", "surrogateescape"); name = "pasted.eml"
    else:
        raise HTTPException(400, "Provide an .eml file or raw_text")
    if len(raw) > 25 * 1024 * 1024: raise HTTPException(413, "Message too large (25 MB limit)")
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _run, raw, name, _actor(x_analyst), "upload", persist)
    return JSONResponse(json.loads(json.dumps(result, default=str)))

@app.post("/api/analyze/batch")
async def analyze_batch(files: List[UploadFile] = File(...), x_analyst: Optional[str] = Header(None)):
    loop = asyncio.get_event_loop(); out = []
    for f in files:
        raw = await f.read()
        try:
            r = await loop.run_in_executor(None, _run, raw, f.filename, _actor(x_analyst), "batch", True)
            out.append({"file": f.filename, "case_id": r["id"], "score": r["score"]["score"], "label": r["score"]["label"], "threat": r["threat"]["primary"]})
        except Exception as e:
            out.append({"file": f.filename, "error": str(e)})
    return out

@app.get("/api/samples")
def samples():
    out = []
    for p in sorted(glob.glob(os.path.join(SAMPLES, "*.eml"))):
        raw = open(p, "rb").read()
        subj = ""; frm = ""
        for line in raw.decode("utf-8", "ignore").splitlines():
            if line.lower().startswith("subject:"): subj = line[8:].strip()
            if line.lower().startswith("from:"): frm = line[5:].strip()
            if subj and frm: break
        out.append({"name": os.path.basename(p), "subject": subj, "from": frm, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()[:16]})
    return out

@app.post("/api/samples/{name}/analyze")
async def analyze_sample(name: str, x_analyst: Optional[str] = Header(None)):
    p = os.path.join(SAMPLES, os.path.basename(name))
    if not os.path.exists(p): raise HTTPException(404, "sample not found")
    raw = open(p, "rb").read()
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _run, raw, os.path.basename(p), _actor(x_analyst), "sample", True)
    return JSONResponse(json.loads(json.dumps(result, default=str)))

@app.post("/api/samples/load_all")
async def load_all_samples(x_analyst: Optional[str] = Header(None)):
    loop = asyncio.get_event_loop(); out = []
    for p in sorted(glob.glob(os.path.join(SAMPLES, "*.eml"))):
        raw = open(p, "rb").read()
        r = await loop.run_in_executor(None, _run, raw, os.path.basename(p), _actor(x_analyst), "sample", True)
        out.append({"file": os.path.basename(p), "case_id": r["id"], "score": r["score"]["score"], "label": r["score"]["label"], "threat": r["threat"]["primary"], "campaign_id": r.get("campaign_id")})
    return out

@app.get("/api/cases")
def cases(q: str = "", verdict: str = "", campaign: str = "", limit: int = 200, job: str = "", source: str = "", min_score: Optional[float] = None, mailbox: str = ""):
    return store.list_cases(q=q, verdict=verdict, campaign=campaign, limit=limit, job=job, source=source, min_score=min_score, mailbox=mailbox)

@app.get("/api/mailboxes")
def mailboxes():
    """Mailbox selector: every mail ID / import file that has analysed cases, with counts (feeds the 'select a mailbox first' UI)."""
    return store.list_mailboxes()

@app.get("/api/cases/{cid}")
def case(cid: str, x_analyst: Optional[str] = Header(None)):
    c = store.get_case(cid)
    if not c: raise HTTPException(404, "case not found")
    store.log_custody(cid, _actor(x_analyst), "view", "case opened in dashboard")
    return JSONResponse(json.loads(json.dumps(c, default=str)))

class CaseUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None

@app.patch("/api/cases/{cid}")
def update_case(cid: str, body: CaseUpdate, x_analyst: Optional[str] = Header(None)):
    if not store.get_case(cid): raise HTTPException(404, "case not found")
    store.update_case(cid, _actor(x_analyst), status=body.status, notes=body.notes, tags=body.tags)
    return {"ok": True}

@app.get("/api/cases/{cid}/report.pdf")
def case_report(cid: str, x_analyst: Optional[str] = Header(None)):
    c = store.get_case(cid)
    if not c: raise HTTPException(404, "case not found")
    pdf = report.build_pdf(c, load_org_profile(), analyst=_actor(x_analyst))
    store.log_custody(cid, _actor(x_analyst), "export", f"PDF report generated sha256={hashlib.sha256(pdf).hexdigest()[:16]}")
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'inline; filename="MailTrace_{cid}.pdf"'})

@app.get("/api/cases/{cid}/report.json")
def case_report_json(cid: str):
    c = store.get_case(cid)
    if not c: raise HTTPException(404, "case not found")
    return JSONResponse(json.loads(json.dumps(c, default=str)))

@app.get("/api/cases/{cid}/iocs.csv")
def case_iocs(cid: str):
    c = store.get_case(cid)
    if not c: raise HTTPException(404, "case not found")
    lines = ["type,value"] + [f'{i["type"]},"{i["value"]}"' for i in c["indicators"]]
    return Response("\n".join(lines), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="iocs_{cid}.csv"'})

@app.get("/api/cases/{cid}/evidence.eml")
def case_evidence(cid: str, x_analyst: Optional[str] = Header(None)):
    c = store.get_case(cid)
    if not c: raise HTTPException(404, "case not found")
    p = store.evidence_path(c["sha256"])
    if not p: raise HTTPException(404, "evidence missing")
    store.log_custody(cid, _actor(x_analyst), "export", "original evidence .eml downloaded")
    return FileResponse(p, media_type="message/rfc822", filename=f"evidence_{cid}.eml")

@app.get("/api/cases/{cid}/verify")
def case_verify(cid: str):
    c = store.get_case(cid)
    if not c: raise HTTPException(404, "case not found")
    return store.verify_evidence(c["sha256"])

@app.get("/api/campaigns")
def campaigns(mailbox: str = ""):
    return store.list_campaigns(mailbox=mailbox)

@app.get("/api/graph")
def graph(limit: int = 60, mailbox: str = ""):
    return store.global_graph(limit, mailbox=mailbox)

@app.get("/api/stats")
def stats(mailbox: str = ""):
    return store.stats(mailbox=mailbox)

@app.get("/api/org")
def org():
    return load_org_profile()

@app.get("/api/lookup/ip/{ip}")
def lookup_ip(ip: str):
    g = intel.geolocate([ip]).get(ip, {})
    g["rdap"] = intel.ip_rdap(ip); g["ptr"] = intel.get_ptr(ip)
    return g

@app.get("/api/lookup/domain/{domain}")
def lookup_domain(domain: str):
    return {"rdap": intel.domain_rdap(domain), "spf": intel.get_spf_record(domain), "dmarc": intel.get_dmarc(domain), "mx": intel.get_mx(domain)}

@app.get("/api/events")
async def events():
    q: asyncio.Queue = asyncio.Queue(); _subscribers.append(q)
    async def gen():
        try:
            yield "event: hello\ndata: {}\n\n"
            while True:
                try:
                    evt = await asyncio.wait_for(q.get(), timeout=20)
                    yield f"event: {evt.get('type','case')}\ndata: {json.dumps(evt, default=str)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            if q in _subscribers: _subscribers.remove(q)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ---- settings / administration (used by the desktop Settings page) ----
@app.get("/api/settings")
def get_settings():
    return {"settings": load_settings(), "org": load_org_profile(), "data_dir": DATA_DIR, "offline_active": intel.OFFLINE}

class SettingsUpdate(BaseModel):
    offline: Optional[bool] = None
    analyst: Optional[str] = None
    retention_days: Optional[int] = None

@app.put("/api/settings")
def put_settings(body: SettingsUpdate):
    s = save_settings({k: v for k, v in body.model_dump().items() if v is not None})
    if body.offline is not None:
        intel.OFFLINE = bool(body.offline)          # takes effect immediately, no restart needed
    return {"settings": s, "offline_active": intel.OFFLINE}

class OrgUpdate(BaseModel):
    organization: Optional[str] = None
    domains: Optional[List[str]] = None
    esp: Optional[str] = None
    partners: Optional[List[str]] = None
    vips: Optional[List[Dict[str, str]]] = None
    retention_days: Optional[int] = None

@app.put("/api/org")
def put_org(body: OrgUpdate):
    return save_org_profile({k: v for k, v in body.model_dump().items() if v is not None})

@app.post("/api/admin/reset")
def admin_reset(x_analyst: Optional[str] = Header(None)):
    r = store.reset_store()
    logging.getLogger("uvicorn.error").warning("case store reset by %s: %s", _actor(x_analyst), r)
    return r

@app.get("/api/admin/export/{cid}/{kind}")
def admin_export(cid: str, kind: str, path: str = Query(...), x_analyst: Optional[str] = Header(None)):
    """Desktop only: write a report/artifact straight to a path chosen in a native Save dialog."""
    if os.environ.get("MAILTRACE_DESKTOP") != "1": raise HTTPException(403, "desktop only")
    c = store.get_case(cid)
    if not c: raise HTTPException(404, "case not found")
    if kind == "pdf":
        data = report.build_pdf(c, load_org_profile(), analyst=_actor(x_analyst))
    elif kind == "json":
        data = json.dumps(c, default=str, indent=2).encode("utf-8")
    elif kind == "csv":
        data = ("\n".join(["type,value"] + [f'{i["type"]},"{i["value"]}"' for i in c["indicators"]])).encode("utf-8")
    elif kind == "eml":
        p = store.evidence_path(c["sha256"])
        if not p: raise HTTPException(404, "evidence missing")
        data = open(p, "rb").read()
    else:
        raise HTTPException(400, "kind must be pdf|json|csv|eml")
    with open(path, "wb") as f: f.write(data)
    store.log_custody(cid, _actor(x_analyst), "export", f"{kind} exported to {os.path.basename(path)} sha256={hashlib.sha256(data).hexdigest()[:16]}")
    return {"ok": True, "path": path, "bytes": len(data)}

# ------------------------------------------------------------ bulk ingestion: mail sources, imports, jobs ----
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

class SourceIn(BaseModel):
    name: Optional[str] = None
    kind: Optional[str] = "imap"
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    secret: Optional[str] = None            # app password / OAuth2 access token; never returned by the API
    auth: Optional[str] = None              # password | oauth2 | plain-insecure (lab servers on port 143)
    folders: Optional[List[str]] = None
    since: Optional[str] = None             # ISO date: only messages on/after this date
    mode: Optional[str] = None              # once | monitor | idle
    interval_min: Optional[int] = None
    unwrap: Optional[bool] = None           # unpack "forward as attachment" / journaling wrappers
    enabled: Optional[bool] = None
    authorization: Optional[str] = None     # who authorised monitoring of this mailbox (recorded in custody)

@app.get("/api/sources")
def sources_list():
    return ingest.list_sources()

@app.post("/api/sources")
def sources_create(body: SourceIn, x_analyst: Optional[str] = Header(None)):
    d = {k: v for k, v in body.model_dump().items() if v is not None}
    if not d.get("host") or not d.get("username"): raise HTTPException(400, "host and username are required")
    src = ingest.save_source(d)
    logging.getLogger("uvicorn.error").info("mail source %s (%s@%s) added by %s", src["id"], src["username"], src["host"], _actor(x_analyst))
    return src

@app.put("/api/sources/{sid}")
def sources_update(sid: str, body: SourceIn):
    if not ingest.get_source(sid): raise HTTPException(404, "source not found")
    return ingest.save_source({k: v for k, v in body.model_dump().items() if v is not None}, sid)

@app.delete("/api/sources/{sid}")
def sources_delete(sid: str):
    if not ingest.delete_source(sid): raise HTTPException(404, "source not found")
    return {"ok": True}

@app.post("/api/sources/test")
async def sources_test(body: SourceIn, sid: str = Query("")):
    """Connect + list folders + count messages. Nothing is fetched or stored."""
    cfg = {k: v for k, v in body.model_dump().items() if v is not None}
    if sid: cfg["id"] = sid
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, ingest.test_source, cfg)

class RunIn(BaseModel):
    mode: Optional[str] = "backfill"        # backfill | incremental
    limit: Optional[int] = 0                # 0 = no limit
    deep_min_score: Optional[float] = None  # only enrich cases with provisional score >= this (speeds up huge jobs)

@app.post("/api/sources/{sid}/run")
def sources_run(sid: str, body: RunIn = None, x_analyst: Optional[str] = Header(None)):
    body = body or RunIn()
    try:
        return ingest.start_imap_job(sid, _actor(x_analyst), mode=body.mode or "backfill", limit=body.limit or 0, deep_min_score=body.deep_min_score)
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.post("/api/import/upload")
async def import_upload(files: List[UploadFile] = File(...), unwrap: bool = Form(True), deep_min_score: Optional[float] = Form(None), x_analyst: Optional[str] = Header(None)):
    """Bulk import: .mbox (Google Takeout / Thunderbird / Apple Mail), .zip of .eml/.msg, or many .eml at once.
    Files are streamed to disk (a 2 GB Takeout never has to fit in memory) and processed by the job runner."""
    paths, names = [], []
    for f in files:
        safe = os.path.basename(f.filename or "upload.bin").replace("..", "_")
        dest = os.path.join(UPLOAD_DIR, f"{int(time.time())}_{hashlib.sha1(safe.encode()).hexdigest()[:6]}_{safe}")
        with open(dest, "wb") as out:
            while True:
                chunk = await f.read(1 << 20)
                if not chunk: break
                out.write(chunk)
        paths.append(dest); names.append(safe)
    if not paths: raise HTTPException(400, "no files")
    return ingest.start_file_job(paths, _actor(x_analyst), unwrap=unwrap, cleanup=True, deep_min_score=deep_min_score, names=names)

class ImportPathIn(BaseModel):
    paths: List[str]
    unwrap: Optional[bool] = True
    deep_min_score: Optional[float] = None

@app.post("/api/import/path")
def import_path(body: ImportPathIn, x_analyst: Optional[str] = Header(None)):
    """Desktop only: import from local paths chosen in a native picker (folder of .eml, .mbox, .zip) without copying them."""
    if os.environ.get("MAILTRACE_DESKTOP") != "1": raise HTTPException(403, "desktop only")
    paths = [p for p in body.paths if os.path.exists(p)]
    if not paths: raise HTTPException(400, "no existing paths")
    return ingest.start_file_job(paths, _actor(x_analyst), unwrap=bool(body.unwrap), cleanup=False, deep_min_score=body.deep_min_score)

@app.get("/api/jobs")
def jobs_list(limit: int = 30):
    return ingest.list_jobs(limit)

@app.get("/api/jobs/{jid}")
def jobs_get(jid: str):
    j = ingest.get_job(jid)
    if not j: raise HTTPException(404, "job not found")
    return j

@app.post("/api/jobs/{jid}/cancel")
def jobs_cancel(jid: str):
    if not ingest.cancel_job(jid): raise HTTPException(404, "job not running")
    return {"ok": True}

# ---- frontend ----
app.mount("/static", StaticFiles(directory=FRONTEND), name="static")

@app.get("/", response_class=HTMLResponse)
def index():
    return open(os.path.join(FRONTEND, "index.html"), encoding="utf-8").read()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), reload=False)
