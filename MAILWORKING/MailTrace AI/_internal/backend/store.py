"""
Case store: SQLite persistence, evidence preservation (raw .eml kept immutable, sha256 sealed),
chain-of-custody audit log, campaign clustering via shared-indicator graph, and search.
"""
import os, json, sqlite3, time, hashlib, threading, re
from typing import Dict, Any, List, Optional
import networkx as nx

from analyzer.common import DATA_DIR
ROOT = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DATA_DIR, "mailtrace.db")
EVIDENCE_DIR = os.path.join(DATA_DIR, "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)
_lock = threading.Lock()

def _conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    c.row_factory = sqlite3.Row
    return c

def init():
    with _conn() as c:
        try: c.execute("PRAGMA journal_mode=WAL")           # readers never block the bulk-ingestion writers
        except sqlite3.OperationalError: pass
        c.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY, sha256 TEXT, created_at TEXT, analyzed_at TEXT, filename TEXT, subject TEXT, sender TEXT, sender_domain TEXT,
            recipient TEXT, score REAL, verdict TEXT, threat TEXT, scenario TEXT, origin_ip TEXT, origin_country TEXT, origin_city TEXT,
            campaign_id TEXT, status TEXT DEFAULT 'open', analyst_notes TEXT DEFAULT '', tags TEXT DEFAULT '[]', result_json TEXT, source TEXT DEFAULT 'upload'
        );
        CREATE TABLE IF NOT EXISTS indicators (
            case_id TEXT, type TEXT, value TEXT, PRIMARY KEY (case_id, type, value)
        );
        CREATE TABLE IF NOT EXISTS custody (
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, ts TEXT, actor TEXT, action TEXT, detail TEXT, hash_before TEXT, hash_after TEXT
        );
        CREATE TABLE IF NOT EXISTS campaigns (
            id TEXT PRIMARY KEY, name TEXT, created_at TEXT, updated_at TEXT, member_count INTEGER, shared_indicators TEXT, threat TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_ind_value ON indicators(type, value);
        CREATE INDEX IF NOT EXISTS idx_cases_campaign ON cases(campaign_id);
        """)
        # additive migrations (older databases): where the message came from + which ingestion job produced it
        for col, ddl in (("source_ref", "TEXT DEFAULT ''"), ("job_id", "TEXT"), ("mailbox", "TEXT DEFAULT ''")):
            try: c.execute(f"ALTER TABLE cases ADD COLUMN {col} {ddl}")
            except sqlite3.OperationalError: pass
        c.execute("CREATE INDEX IF NOT EXISTS idx_cases_sha ON cases(sha256)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_cases_job ON cases(job_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_cases_mailbox ON cases(mailbox)")
        # backfill mailbox for rows written before the column existed (imap rows are filled by ingest.init, which knows the sources)
        for r in c.execute("SELECT id, source, source_ref FROM cases WHERE mailbox='' OR mailbox IS NULL").fetchall():
            mb = mailbox_label(r["source"], r["source_ref"])
            if mb: c.execute("UPDATE cases SET mailbox=? WHERE id=?", (mb, r["id"]))

MAILBOX_MANUAL, MAILBOX_DEMO = "manual upload", "demo corpus"

def mailbox_label(source: Optional[str], source_ref: Optional[str] = "", username: str = "") -> str:
    """Human-facing mailbox identity a case belongs to: the mail ID for IMAP, the export file for bulk imports."""
    if source == "imap":
        return username or ""
    if source == "import":
        ref = (source_ref or "")[7:] if (source_ref or "").startswith("file://") else (source_ref or "")
        return re.split(r"[!#]| \| ", ref, 1)[0].strip() or "bulk import"
    if source == "sample":
        return MAILBOX_DEMO
    return MAILBOX_MANUAL

def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def log_custody(case_id: str, actor: str, action: str, detail: str = "", hash_before: str = "", hash_after: str = ""):
    with _conn() as c:
        c.execute("INSERT INTO custody(case_id, ts, actor, action, detail, hash_before, hash_after) VALUES (?,?,?,?,?,?,?)",
                  (case_id, _now(), actor, action, detail, hash_before, hash_after))

def _indicators(result: Dict[str, Any]) -> List[tuple]:
    io = result["iocs"]; out = set()
    if io.get("sender"): out.add(("sender", io["sender"]))
    if io.get("reply_to"): out.add(("reply_to", io["reply_to"]))
    sd = result["headers"]["from"]["registered_domain"]
    from analyzer.common import FREEMAIL, ESP_ALL, load_org_profile
    _org = load_org_profile(); _own = {d.lower() for d in _org.get("domains", [])} | {d.lower() for d in _org.get("partners", [])}
    if sd and sd not in FREEMAIL and sd not in _own: out.add(("sender_domain", sd))   # the victim's own domain links nothing
    if io.get("origin_ip"):
        g = result["geo"].get(io["origin_ip"], {})
        if "EMAIL_PROVIDER" not in g.get("tags", []): out.add(("origin_ip", io["origin_ip"]))
    for d in io.get("domains", []):
        if d and d != sd and d not in ESP_ALL and d not in FREEMAIL and d not in ("svnit.ac.in", "google.com", "wikimedia.org", "razorpay.com"):
            out.add(("url_domain", d))
    for a in io.get("attachment_hashes", []): out.add(("file_sha256", a["sha256"]))
    for w in io.get("crypto_wallets", []): out.add(("wallet", w))
    for u in io.get("upi_ids", []): out.add(("upi", u))
    for p in io.get("phones", []): out.add(("phone", re.sub(r"\D", "", p)))
    subj = re.sub(r"\W+", " ", result["headers"]["subject"].lower()).strip()
    if subj: out.add(("subject_norm", subj[:80]))
    return sorted(out)

STRONG = {"sender", "reply_to", "sender_domain", "origin_ip", "url_domain", "file_sha256", "wallet", "upi", "phone"}

def case_by_sha(sha256: str) -> Optional[Dict[str, Any]]:
    """Dedupe hook for bulk ingestion: the case that already holds this exact message, if any."""
    with _conn() as c:
        r = c.execute("SELECT id, score, verdict, threat, campaign_id, created_at FROM cases WHERE sha256=?", (sha256,)).fetchone()
        return dict(r) if r else None

def save_case(result: Dict[str, Any], raw: bytes, filename: str, actor: str = "system", source: Optional[str] = "upload",
              source_ref: str = "", job_id: Optional[str] = None, recluster_now: bool = True, custody_action: Optional[str] = None,
              mailbox: Optional[str] = None) -> Dict[str, Any]:
    """
    Persist an analysis: seal evidence (write-once), upsert the case row + indicators, append custody.
    Bulk jobs pass recluster_now=False and call recluster() themselves every N messages / at the end
    (campaign clustering is O(cases) and would otherwise run once per message).
    """
    cid = result["id"]
    sha = result["sha256"]
    with _lock:
        # evidence preservation: immutable copy, write-once
        ev_path = os.path.join(EVIDENCE_DIR, f"{sha}.eml")
        if not os.path.exists(ev_path):
            with open(ev_path, "wb") as f: f.write(raw)
            os.chmod(ev_path, 0o444)
        h = result["headers"]; a = result["attribution"]; g = a.get("origin_geo") or {}
        with _conn() as c:
            existing_row = c.execute("SELECT id, created_at FROM cases WHERE id=?", (cid,)).fetchone(); existing = existing_row
            c.execute("""INSERT OR REPLACE INTO cases(id, sha256, created_at, analyzed_at, filename, subject, sender, sender_domain, recipient, score, verdict, threat, scenario,
                         origin_ip, origin_country, origin_city, campaign_id, status, analyst_notes, tags, result_json, source, source_ref, job_id, mailbox)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, COALESCE((SELECT campaign_id FROM cases WHERE id=?), NULL), COALESCE((SELECT status FROM cases WHERE id=?), 'open'),
                         COALESCE((SELECT analyst_notes FROM cases WHERE id=?), ''), COALESCE((SELECT tags FROM cases WHERE id=?), '[]'), ?,
                         COALESCE(?, (SELECT source FROM cases WHERE id=?), 'upload'), COALESCE(?, (SELECT source_ref FROM cases WHERE id=?), ''), COALESCE(?, (SELECT job_id FROM cases WHERE id=?)),
                         COALESCE(?, NULLIF((SELECT mailbox FROM cases WHERE id=?), ''), ?))""",
                      (cid, sha, (existing_row["created_at"] if existing_row else _now()), result["analyzed_at"], filename, h["subject"], h["from"]["address"], h["from"]["registered_domain"], h["to"][:200],
                       result["score"]["score"], result["score"]["verdict"], result["threat"]["primary"], a["scenario"], a.get("origin_ip"), g.get("country"), g.get("city"),
                       cid, cid, cid, cid, json.dumps(result, default=str), source, cid, (source_ref[:300] if source_ref is not None else None), cid, job_id, cid,
                       (mailbox[:200] if mailbox else None), cid, mailbox_label(source, source_ref)))
            c.execute("DELETE FROM indicators WHERE case_id=?", (cid,))
            c.executemany("INSERT OR IGNORE INTO indicators(case_id, type, value) VALUES (?,?,?)", [(cid, t, v) for t, v in _indicators(result)])
        log_custody(cid, actor, custody_action or ("ingest" if not existing else "re-analyse"), f"file={filename} size={len(raw)}B source={source}" + (f" ref={source_ref}" if source_ref else ""), "", sha)
        camp = recluster() if recluster_now else {}
    return {"case_id": cid, "campaign_id": camp.get(cid)}

CAMPAIGN_MIN_SCORE = 35

def recluster() -> Dict[str, str]:
    """
    Campaign = connected component of *suspicious-or-worse* cases (score >= 35) that share STRONG indicators.
    Scale rules (learned from 1,000-mailbox imports): clean cases never join a campaign; an indicator that occurs in
    more clean cases than suspicious ones is common/benign infrastructure (an ESP relay IP, a colleague's address)
    and is not used as a link. Edges use a star per indicator (components are identical, O(n) instead of O(n²)).
    Deterministic campaign ids from the sorted member set.
    """
    with _conn() as c:
        rows = c.execute("SELECT case_id, type, value FROM indicators WHERE type IN (%s)" % ",".join("?" * len(STRONG)), tuple(STRONG)).fetchall()
        cases = {r["id"]: dict(r) for r in c.execute("SELECT id, threat, verdict, score FROM cases").fetchall()}
    sus = {cid for cid, x in cases.items() if (x.get("score") or 0) >= CAMPAIGN_MIN_SCORE}
    G = nx.Graph()
    for cid in sus: G.add_node(cid)
    by_ind: Dict[tuple, List[str]] = {}
    for r in rows:
        by_ind.setdefault((r["type"], r["value"]), []).append(r["case_id"])
    shared: Dict[str, set] = {}
    for (t, v), members in by_ind.items():
        mal = [m for m in members if m in sus]
        if len(mal) < 2:
            continue
        if len(members) - len(mal) > len(mal):          # seen in more legitimate mail than malicious → benign infrastructure
            continue
        hub = mal[0]
        for m in mal:
            if m != hub: G.add_edge(hub, m)
            shared.setdefault(m, set()).add(f"{t}:{v}")
    mapping = {}
    with _conn() as c:
        c.execute("DELETE FROM campaigns")
        c.execute("UPDATE cases SET campaign_id=NULL WHERE campaign_id IS NOT NULL AND (score < ? OR id NOT IN (SELECT case_id FROM indicators))", (CAMPAIGN_MIN_SCORE,))
        for comp in nx.connected_components(G):
            comp = sorted(comp)
            if len(comp) < 2:
                for x in comp: c.execute("UPDATE cases SET campaign_id=NULL WHERE id=?", (x,))
                continue
            camp_id = "CAMP-" + hashlib.sha1("|".join(comp).encode()).hexdigest()[:8].upper()
            inds = set()
            for x in comp: inds |= shared.get(x, set())
            threats = [cases[x]["threat"] for x in comp if x in cases]
            threat = max(set(threats), key=threats.count) if threats else ""
            name = _campaign_name(inds, threat)
            c.execute("INSERT INTO campaigns(id, name, created_at, updated_at, member_count, shared_indicators, threat) VALUES (?,?,?,?,?,?,?)",
                      (camp_id, name, _now(), _now(), len(comp), json.dumps(sorted(inds)), threat))
            for x in comp:
                c.execute("UPDATE cases SET campaign_id=? WHERE id=?", (camp_id, x)); mapping[x] = camp_id
    return mapping

def _campaign_name(inds: set, threat: str) -> str:
    doms = [i.split(":", 1)[1] for i in inds if i.startswith(("url_domain:", "sender_domain:"))]
    ips = [i.split(":", 1)[1] for i in inds if i.startswith("origin_ip:")]
    senders = [i.split(":", 1)[1] for i in inds if i.startswith(("sender:", "reply_to:"))]
    key = (doms or senders or ips or ["unknown"])[0]
    return f"{threat.replace('_', ' ').title()} campaign via {key}"

def list_cases(q: str = "", verdict: str = "", campaign: str = "", limit: int = 200, job: str = "", source: str = "", min_score: float = None, mailbox: str = "") -> List[Dict[str, Any]]:
    sql = "SELECT id, created_at, filename, subject, sender, sender_domain, recipient, score, verdict, threat, scenario, origin_ip, origin_country, origin_city, campaign_id, status, tags, source, source_ref, job_id, mailbox FROM cases WHERE 1=1"
    args: List[Any] = []
    if job: sql += " AND job_id=?"; args.append(job)
    if mailbox: sql += " AND mailbox=?"; args.append(mailbox)
    if source: sql += " AND source=?"; args.append(source)
    if min_score is not None: sql += " AND score>=?"; args.append(min_score)
    if q:
        sql += " AND (subject LIKE ? OR sender LIKE ? OR origin_ip LIKE ? OR sender_domain LIKE ? OR id IN (SELECT case_id FROM indicators WHERE value LIKE ?))"
        args += [f"%{q}%"] * 5
    if verdict: sql += " AND verdict=?"; args.append(verdict)
    if campaign: sql += " AND campaign_id=?"; args.append(campaign)
    sql += " ORDER BY created_at DESC LIMIT ?"; args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(sql, args).fetchall()]

def get_case(cid: str) -> Optional[Dict[str, Any]]:
    with _conn() as c:
        r = c.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
        if not r: return None
        d = dict(r); d["result"] = json.loads(d.pop("result_json")); d["tags"] = json.loads(d["tags"] or "[]")
        d["custody"] = [dict(x) for x in c.execute("SELECT ts, actor, action, detail, hash_before, hash_after FROM custody WHERE case_id=? ORDER BY id", (cid,)).fetchall()]
        d["indicators"] = [dict(x) for x in c.execute("SELECT type, value FROM indicators WHERE case_id=?", (cid,)).fetchall()]
        # related cases via shared indicators
        rel = c.execute("""SELECT i2.case_id, i2.type, i2.value, c2.subject, c2.sender, c2.score, c2.verdict FROM indicators i1 JOIN indicators i2 ON i1.type=i2.type AND i1.value=i2.value
                           JOIN cases c2 ON c2.id=i2.case_id WHERE i1.case_id=? AND i2.case_id<>? AND i1.type IN (%s) ORDER BY c2.score DESC LIMIT 400""" % ",".join("?" * len(STRONG)), (cid, cid, *STRONG)).fetchall()
        related: Dict[str, Dict[str, Any]] = {}
        for x in rel:
            if x["case_id"] not in related and len(related) >= 25: continue
            e = related.setdefault(x["case_id"], {"case_id": x["case_id"], "subject": x["subject"], "sender": x["sender"], "score": x["score"], "verdict": x["verdict"], "shared": []})
            e["shared"].append(f"{x['type']}:{x['value']}")
        d["related"] = sorted(related.values(), key=lambda r: -(r["score"] or 0))
        return d

def update_case(cid: str, actor: str, status: str = None, notes: str = None, tags: List[str] = None):
    with _conn() as c:
        if status is not None: c.execute("UPDATE cases SET status=? WHERE id=?", (status, cid))
        if notes is not None: c.execute("UPDATE cases SET analyst_notes=? WHERE id=?", (notes, cid))
        if tags is not None: c.execute("UPDATE cases SET tags=? WHERE id=?", (json.dumps(tags), cid))
    log_custody(cid, actor, "update", json.dumps({k: v for k, v in {"status": status, "notes": (notes or "")[:60], "tags": tags}.items() if v is not None}))

def list_campaigns(mailbox: str = "") -> List[Dict[str, Any]]:
    """Campaigns, optionally scoped to one mailbox: only campaigns that touched that mailbox, members from that mailbox
    listed first; `member_count` stays global (a campaign is cross-mailbox by nature) and `scoped_count` says how many hit this mailbox."""
    with _conn() as c:
        out = []
        for r in c.execute("SELECT * FROM campaigns ORDER BY member_count DESC").fetchall():
            d = dict(r); d["shared_indicators"] = json.loads(d["shared_indicators"])
            d["members"] = [dict(x) for x in c.execute("SELECT id, subject, sender, score, verdict, threat, origin_ip, origin_country, created_at, recipient, mailbox FROM cases WHERE campaign_id=? ORDER BY created_at", (d["id"],)).fetchall()]
            if mailbox:
                mine = [m for m in d["members"] if m.get("mailbox") == mailbox]
                if not mine: continue
                d["scoped_count"] = len(mine); d["scoped_mailbox"] = mailbox
                d["members"] = mine + [m for m in d["members"] if m.get("mailbox") != mailbox]
            out.append(d)
        return out

def list_mailboxes() -> List[Dict[str, Any]]:
    """Mailbox selector data: one row per mail ID / import file with counts."""
    with _conn() as c:
        rows = c.execute("""SELECT COALESCE(NULLIF(mailbox,''), 'unassigned') AS mailbox, source, COUNT(*) AS total,
                                   SUM(CASE WHEN score>=60 THEN 1 ELSE 0 END) AS malicious, SUM(CASE WHEN score>=35 AND score<60 THEN 1 ELSE 0 END) AS suspicious,
                                   SUM(CASE WHEN status='open' AND score>=60 THEN 1 ELSE 0 END) AS open_high, MAX(created_at) AS last_at, MIN(created_at) AS first_at,
                                   COUNT(DISTINCT campaign_id) AS campaigns
                            FROM cases GROUP BY 1, 2 ORDER BY last_at DESC""").fetchall()
    return [dict(r) for r in rows]

def global_graph(limit_cases: int = 60, mailbox: str = "") -> Dict[str, Any]:
    """Cross-case infrastructure graph for the Link Analysis view (optionally one mailbox only)."""
    with _conn() as c:
        if mailbox:
            cases = [dict(r) for r in c.execute("SELECT id, subject, score, verdict, campaign_id, threat FROM cases WHERE mailbox=? ORDER BY created_at DESC LIMIT ?", (mailbox, limit_cases)).fetchall()]
        else:
            cases = [dict(r) for r in c.execute("SELECT id, subject, score, verdict, campaign_id, threat FROM cases ORDER BY created_at DESC LIMIT ?", (limit_cases,)).fetchall()]
        ids = [x["id"] for x in cases]
        if not ids: return {"nodes": [], "edges": []}
        inds = [dict(r) for r in c.execute("SELECT case_id, type, value FROM indicators WHERE case_id IN (%s) AND type IN (%s)" % (",".join("?" * len(ids)), ",".join("?" * len(STRONG))), (*ids, *STRONG)).fetchall()]
    nodes, edges = {}, []
    for x in cases:
        nodes[f"case:{x['id']}"] = {"id": f"case:{x['id']}", "type": "email", "label": (x["subject"] or "(no subject)")[:38], "score": x["score"], "campaign": x["campaign_id"], "case_id": x["id"]}
    deg: Dict[str, int] = {}
    for i in inds:
        nid = f"{i['type']}:{i['value']}"
        deg[nid] = deg.get(nid, 0) + 1
    for i in inds:
        nid = f"{i['type']}:{i['value']}"
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": i["type"], "label": i["value"][:40], "degree": deg[nid]}
        edges.append({"source": f"case:{i['case_id']}", "target": nid, "rel": i["type"]})
    return {"nodes": list(nodes.values()), "edges": edges}

def reset_store() -> Dict[str, Any]:
    """Delete every case, indicator, custody record, campaign and sealed evidence file (used by the desktop 'Reset case store')."""
    removed = 0
    with _lock:
        with _conn() as c:
            n = c.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
            c.executescript("DELETE FROM indicators; DELETE FROM custody; DELETE FROM campaigns; DELETE FROM cases;")
        for fn in os.listdir(EVIDENCE_DIR):
            if fn.endswith(".eml"):
                try: os.remove(os.path.join(EVIDENCE_DIR, fn)); removed += 1
                except Exception: pass
    return {"cases_deleted": int(n), "evidence_files_deleted": removed}

def count_cases() -> int:
    try:
        with _conn() as c:
            return int(c.execute("SELECT COUNT(*) FROM cases").fetchone()[0])
    except Exception:
        return 0

def stats(mailbox: str = "") -> Dict[str, Any]:
    w, a = (" AND mailbox=?", (mailbox,)) if mailbox else ("", ())
    with _conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM cases WHERE 1=1{w}", a).fetchone()[0]
        by_verdict = {r[0]: r[1] for r in c.execute(f"SELECT verdict, COUNT(*) FROM cases WHERE 1=1{w} GROUP BY verdict", a).fetchall()}
        by_threat = {r[0]: r[1] for r in c.execute(f"SELECT threat, COUNT(*) FROM cases WHERE 1=1{w} GROUP BY threat", a).fetchall()}
        by_country = [{"country": r[0], "count": r[1]} for r in c.execute(f"SELECT origin_country, COUNT(*) FROM cases WHERE origin_country IS NOT NULL AND score>=35{w} GROUP BY origin_country ORDER BY 2 DESC LIMIT 8", a).fetchall()]
        by_scenario = {r[0]: r[1] for r in c.execute(f"SELECT scenario, COUNT(*) FROM cases WHERE score>=35{w} GROUP BY scenario", a).fetchall()}
        camps = c.execute(f"SELECT COUNT(DISTINCT campaign_id) FROM cases WHERE campaign_id IS NOT NULL{w}", a).fetchone()[0] if mailbox else c.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
        open_high = c.execute(f"SELECT COUNT(*) FROM cases WHERE status='open' AND score>=60{w}", a).fetchone()[0]
        by_source = {r[0]: r[1] for r in c.execute(f"SELECT source, COUNT(*) FROM cases WHERE 1=1{w} GROUP BY source", a).fetchall()}
        mailboxes = c.execute("SELECT COUNT(DISTINCT mailbox) FROM cases").fetchone()[0]
    return {"total": total, "by_verdict": by_verdict, "by_threat": by_threat, "by_country": by_country, "by_scenario": by_scenario, "campaigns": camps, "open_high": open_high, "by_source": by_source,
            "mailbox": mailbox, "mailboxes": mailboxes}

def evidence_path(sha256: str) -> Optional[str]:
    p = os.path.join(EVIDENCE_DIR, f"{sha256}.eml")
    return p if os.path.exists(p) else None

def verify_evidence(sha256: str) -> Dict[str, Any]:
    p = evidence_path(sha256)
    if not p: return {"ok": False, "reason": "missing"}
    h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return {"ok": h == sha256, "stored_sha256": h, "expected": sha256}

init()
