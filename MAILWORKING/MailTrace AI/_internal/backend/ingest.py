"""
MailTrace AI — bulk ingestion layer.

Replaces "download every .eml by hand and upload it" with pluggable *mail sources* that all feed the same
analysis pipeline (analyzer.engine.analyze_email → store.save_case):

  * IMAP connector   : any mailbox that speaks IMAP (Gmail, Zoho, Outlook.com/M365 with app password or OAuth2
                       XOAUTH2 token, institutional Dovecot/Zimbra/Exchange, NIC*). Read-only by construction
                       (EXAMINE + BODY.PEEK[]), backfill by date, incremental monitor by UID, optional IDLE push.
  * File containers  : .mbox (Google Takeout / Thunderbird / Apple Mail), .zip of .eml/.msg, a folder, or plain
                       .eml — streamed message by message so a 2 GB Takeout never has to fit in RAM.
  * Report mailbox   : "Forward as attachment" wrappers are unpacked (message/rfc822 part) so the ORIGINAL
                       headers are analysed, not the forwarder's.
  * Journal mailbox  : Exchange/Google Workspace journaling wrappers (envelope + attached original) are
                       unpacked the same way.

Each fetched message is: SHA-256 hashed → deduped against the evidence store → sealed (write-once .eml) →
custody-logged ("ingested from imaps://host/INBOX uid 4711 by analyst X") → analysed by a worker pool that
runs a no-network *fast pass* first so a provisional score is available within milliseconds, then a
*deep pass* (live SPF/DMARC, GeoIP, RDAP, Tor) highest-provisional-score-first. Progress is streamed over
the existing SSE feed.

Only the standard library + what the engine already uses (imaplib, ssl, email, mailbox, zipfile, sqlite3,
threading) — no native dependencies, so the desktop build stays pure Python.
"""
from __future__ import annotations

import os, re, io, ssl, json, time, uuid, queue, base64, hashlib, logging, sqlite3, socket, imaplib, mailbox, zipfile, threading, email, email.policy, email.utils
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from analyzer.common import DATA_DIR, load_org_profile
from analyzer import intel
from analyzer.engine import analyze_email
import store

log = logging.getLogger("mailtrace.ingest")

DB_PATH = store.DB_PATH
MAX_MSG_BYTES = 25 * 1024 * 1024
IMAP_BATCH = 50                      # UIDs per FETCH round-trip
WORKERS = max(4, min(8, (os.cpu_count() or 4) * 2))   # I/O-bound (DNS/HTTP) → more threads than cores helps
DEEP_PASS_MIN_SCORE = 0.0            # analyse everything deeply by default; UI can raise it for very large jobs
RECLUSTER_EVERY = 25                 # campaign clustering cadence during bulk jobs

_publish: Callable[[Dict[str, Any]], None] = lambda evt: None   # set by main.py (SSE fan-out)
_lock = threading.Lock()


def set_publisher(fn: Callable[[Dict[str, Any]], None]) -> None:
    global _publish
    _publish = fn


# --------------------------------------------------------------------------------------------- secrets ----
def _secret_key() -> bytes:
    """Per-installation key kept next to the data (0600). Windows: DPAPI would be the production answer; this
    keeps mailbox passwords out of plain sight in settings/DB without adding native dependencies."""
    p = os.path.join(DATA_DIR, ".mailtrace.key")
    if not os.path.exists(p):
        k = os.urandom(32)
        with open(p, "wb") as f:
            f.write(k)
        try: os.chmod(p, 0o600)
        except OSError: pass
    return open(p, "rb").read()


def _obfuscate(secret: str) -> str:
    if not secret: return ""
    k = hashlib.sha256(_secret_key()).digest()
    b = secret.encode("utf-8")
    x = bytes(c ^ k[i % len(k)] for i, c in enumerate(b))
    return "enc1:" + base64.urlsafe_b64encode(x).decode("ascii")


def _reveal(blob: str) -> str:
    if not blob: return ""
    if not blob.startswith("enc1:"): return blob
    k = hashlib.sha256(_secret_key()).digest()
    x = base64.urlsafe_b64decode(blob[5:])
    return bytes(c ^ k[i % len(k)] for i, c in enumerate(x)).decode("utf-8", "replace")


# ------------------------------------------------------------------------------------------ persistence ----
def _conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def init() -> None:
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS sources (
            id TEXT PRIMARY KEY, name TEXT, kind TEXT, host TEXT, port INTEGER, username TEXT, secret TEXT, auth TEXT DEFAULT 'password',
            folders TEXT DEFAULT '["INBOX"]', since TEXT, mode TEXT DEFAULT 'once', interval_min INTEGER DEFAULT 5, unwrap INTEGER DEFAULT 1,
            enabled INTEGER DEFAULT 1, state TEXT DEFAULT '{}', created_at TEXT, last_run TEXT, last_error TEXT, authorization TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY, source_id TEXT, kind TEXT, label TEXT, status TEXT, created_at TEXT, started_at TEXT, finished_at TEXT,
            total INTEGER DEFAULT 0, fetched INTEGER DEFAULT 0, analysed INTEGER DEFAULT 0, duplicates INTEGER DEFAULT 0, errors INTEGER DEFAULT 0,
            malicious INTEGER DEFAULT 0, suspicious INTEGER DEFAULT 0, actor TEXT, detail TEXT DEFAULT '', error TEXT, enriched INTEGER DEFAULT 0, phase TEXT
        );
        CREATE TABLE IF NOT EXISTS job_items (
            job_id TEXT, seq INTEGER, ref TEXT, sha256 TEXT, case_id TEXT, status TEXT, score REAL, label TEXT, error TEXT, PRIMARY KEY (job_id, seq)
        );
        """)
        for col, ddl in (("enriched", "INTEGER DEFAULT 0"), ("phase", "TEXT")):
            try: c.execute(f"ALTER TABLE jobs ADD COLUMN {col} {ddl}")
            except sqlite3.OperationalError: pass
        # older databases: give IMAP cases their mail ID (source_ref = imap://host/... ; the job row knows the source)
        try:
            for r in c.execute("""SELECT ca.id, s.username FROM cases ca JOIN jobs j ON j.id = ca.job_id JOIN sources s ON s.id = j.source_id
                                  WHERE ca.source='imap' AND (ca.mailbox='' OR ca.mailbox IS NULL)""").fetchall():
                c.execute("UPDATE cases SET mailbox=? WHERE id=?", (r["username"], r["id"]))
            c.execute("UPDATE cases SET mailbox=source_ref WHERE source='imap' AND (mailbox='' OR mailbox IS NULL)")
        except sqlite3.OperationalError:
            pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _public_source(r: sqlite3.Row | Dict[str, Any]) -> Dict[str, Any]:
    d = dict(r)
    d["has_secret"] = bool(d.pop("secret", ""))
    d["folders"] = json.loads(d.get("folders") or "[]")
    d["state"] = json.loads(d.get("state") or "{}")
    d["unwrap"] = bool(d.get("unwrap", 1)); d["enabled"] = bool(d.get("enabled", 1))
    return d


def list_sources() -> List[Dict[str, Any]]:
    with _conn() as c:
        return [_public_source(r) for r in c.execute("SELECT * FROM sources ORDER BY created_at").fetchall()]


def get_source(sid: str, with_secret: bool = False) -> Optional[Dict[str, Any]]:
    with _conn() as c:
        r = c.execute("SELECT * FROM sources WHERE id=?", (sid,)).fetchone()
    if not r: return None
    d = _public_source(r)
    if with_secret: d["secret"] = _reveal(r["secret"] or "")
    return d


def save_source(data: Dict[str, Any], sid: Optional[str] = None) -> Dict[str, Any]:
    cur = get_source(sid, with_secret=True) if sid else None
    sid = sid or ("SRC-" + uuid.uuid4().hex[:8].upper())
    folders = data.get("folders") if data.get("folders") is not None else (cur or {}).get("folders") or ["INBOX"]
    if isinstance(folders, str): folders = [f.strip() for f in re.split(r"[,\n]", folders) if f.strip()]
    secret = data.get("secret")
    secret_blob = _obfuscate(secret) if secret else (_obfuscate(cur["secret"]) if cur and cur.get("secret") else "")
    row = {
        "id": sid, "name": data.get("name") or (cur or {}).get("name") or data.get("username") or "Mailbox",
        "kind": data.get("kind") or (cur or {}).get("kind") or "imap",
        "host": (data.get("host") or (cur or {}).get("host") or "").strip(), "port": int(data.get("port") or (cur or {}).get("port") or 993),
        "username": (data.get("username") or (cur or {}).get("username") or "").strip(), "secret": secret_blob,
        "auth": data.get("auth") or (cur or {}).get("auth") or "password", "folders": json.dumps(folders),
        "since": data.get("since") if data.get("since") is not None else (cur or {}).get("since"),
        "mode": data.get("mode") or (cur or {}).get("mode") or "once", "interval_min": int(data.get("interval_min") or (cur or {}).get("interval_min") or 5),
        "unwrap": 1 if data.get("unwrap", (cur or {}).get("unwrap", True)) else 0, "enabled": 1 if data.get("enabled", (cur or {}).get("enabled", True)) else 0,
        "state": json.dumps((cur or {}).get("state") or {}), "created_at": (cur or {}).get("created_at") or _now(),
        "last_run": (cur or {}).get("last_run"), "last_error": (cur or {}).get("last_error"),
        "authorization": data.get("authorization") if data.get("authorization") is not None else (cur or {}).get("authorization") or "",
    }
    with _conn() as c:
        c.execute("""INSERT OR REPLACE INTO sources(id,name,kind,host,port,username,secret,auth,folders,since,mode,interval_min,unwrap,enabled,state,created_at,last_run,last_error,authorization)
                     VALUES (:id,:name,:kind,:host,:port,:username,:secret,:auth,:folders,:since,:mode,:interval_min,:unwrap,:enabled,:state,:created_at,:last_run,:last_error,:authorization)""", row)
    _monitor.wake()
    return get_source(sid)


def delete_source(sid: str) -> bool:
    with _conn() as c:
        n = c.execute("DELETE FROM sources WHERE id=?", (sid,)).rowcount
    return n > 0


def _update_source(sid: str, **kw) -> None:
    if not kw: return
    with _conn() as c:
        c.execute("UPDATE sources SET " + ", ".join(f"{k}=?" for k in kw) + " WHERE id=?", (*kw.values(), sid))


# ------------------------------------------------------------------------------------------- unwrapping ----
def unwrap_reported(raw: bytes) -> Tuple[bytes, Optional[str]]:
    """
    If the message is a *wrapper* around the email we actually want, return the inner message:
      - user "Forward as attachment" / Outlook "Report phishing" → first message/rfc822 part
      - Exchange / Google Workspace journaling report → attached original
      - .eml attached to a ticket
    Returns (raw, note). note is None when nothing was unwrapped.
    """
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception:
        return raw, None
    if not msg.is_multipart():
        return raw, None
    for part in msg.walk():
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload()
            inner = payload[0] if isinstance(payload, list) and payload else None
            if inner is None:
                continue
            try:
                inner_raw = inner.as_bytes()
            except Exception:
                inner_raw = inner.as_string().encode("utf-8", "surrogateescape")
            if len(inner_raw) > 200 and re.search(rb"(?im)^(from|received|message-id):", inner_raw[:8192]):
                outer_from = email.utils.parseaddr(msg.get("From", ""))[1]
                return inner_raw, f"unwrapped message/rfc822 attachment (reported/journaled by {outer_from or 'unknown'})"
        # .eml attached as application/octet-stream
        fn = (part.get_filename() or "").lower()
        if fn.endswith(".eml") and part.get_content_maintype() != "multipart":
            try:
                inner_raw = part.get_payload(decode=True) or b""
            except Exception:
                inner_raw = b""
            if len(inner_raw) > 200 and re.search(rb"(?im)^(from|received|message-id):", inner_raw[:8192]):
                return inner_raw, f"unwrapped attached file {fn}"
    return raw, None


def _imap_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _imap_date(since: Optional[str]) -> Optional[str]:
    """ISO date → IMAP date (01-Jan-2026)."""
    if not since: return None
    try:
        t = time.strptime(since[:10], "%Y-%m-%d")
        return time.strftime("%d-%b-%Y", t)
    except Exception:
        return None


# ------------------------------------------------------------------------------------------ IMAP source ----
class ImapSource:
    """Read-only IMAP fetcher. Yields (ref, raw_bytes, internal_date)."""

    def __init__(self, src: Dict[str, Any]):
        self.src = src
        self.conn: Optional[imaplib.IMAP4] = None

    # -- connection -------------------------------------------------------------------------------------
    def connect(self) -> imaplib.IMAP4:
        s = self.src
        host, port = s["host"], int(s.get("port") or 993)
        ctx = ssl.create_default_context()
        if port == 143 or s.get("auth") == "plain-insecure":
            conn = imaplib.IMAP4(host, port, timeout=30)
            if "STARTTLS" in conn.capabilities and s.get("auth") != "plain-insecure":
                conn.starttls(ctx)
        else:
            conn = imaplib.IMAP4_SSL(host, port, ssl_context=ctx, timeout=30)
        user, secret = s["username"], s.get("secret", "")
        if s.get("auth") == "oauth2":
            # XOAUTH2 (Gmail / Microsoft 365) — `secret` holds a current access token obtained via the provider's OAuth flow
            auth_string = f"user={user}\x01auth=Bearer {secret}\x01\x01"
            typ, data = conn.authenticate("XOAUTH2", lambda _x: auth_string.encode())
            if typ != "OK":
                raise RuntimeError(f"XOAUTH2 failed: {data}")
        else:
            typ, data = conn.login(user, secret)
            if typ != "OK":
                raise RuntimeError(f"login failed: {data}")
        try:                                   # many servers only advertise IDLE / MOVE / etc. after authentication
            typ, data = conn.capability()
            self.caps = tuple(data[0].decode("ascii", "ignore").upper().split()) if typ == "OK" and data and data[0] else tuple(conn.capabilities)
        except Exception:
            self.caps = tuple(conn.capabilities)
        self.conn = conn
        return conn

    def close(self) -> None:
        try:
            if self.conn is not None:
                try: self.conn.close()
                except Exception: pass
                self.conn.logout()
        except Exception:
            pass
        self.conn = None

    def __enter__(self): self.connect(); return self
    def __exit__(self, *a): self.close()

    # -- discovery --------------------------------------------------------------------------------------
    def list_folders(self) -> List[Dict[str, Any]]:
        typ, data = self.conn.list()
        out = []
        for line in data or []:
            if not line: continue
            m = re.match(rb'\((?P<flags>[^)]*)\)\s+(?P<delim>"[^"]*"|NIL)\s+(?P<name>.+)$', line if isinstance(line, bytes) else line[0])
            if not m: continue
            name = m.group("name").decode("utf-8", "replace").strip()
            if name.startswith('"') and name.endswith('"'): name = name[1:-1]
            flags = m.group("flags").decode("utf-8", "replace")
            if "\\Noselect" in flags: continue
            out.append({"name": name, "flags": flags})
        return out

    def count(self, folder: str, since: Optional[str]) -> int:
        typ, data = self.conn.select(_imap_quote(folder), readonly=True)
        if typ != "OK": return -1
        crit = ["SINCE", _imap_date(since)] if _imap_date(since) else ["ALL"]
        typ, data = self.conn.uid("SEARCH", None, *crit)
        return len((data[0] or b"").split()) if typ == "OK" else -1

    # -- fetch ------------------------------------------------------------------------------------------
    def iter_messages(self, folder: str, since: Optional[str], after_uid: int = 0, limit: int = 0,
                      on_total: Optional[Callable[[int], None]] = None) -> Iterator[Tuple[str, bytes, Optional[str], int]]:
        """Yields (ref, raw, internaldate, uid) with BODY.PEEK[] (never sets \\Seen)."""
        conn = self.conn
        typ, data = conn.select(_imap_quote(folder), readonly=True)          # EXAMINE
        if typ != "OK":
            raise RuntimeError(f"cannot open folder {folder!r}: {data}")
        uidvalidity = (conn.response("UIDVALIDITY")[1] or [b""])[0]
        uidvalidity = uidvalidity.decode() if isinstance(uidvalidity, bytes) else str(uidvalidity or "")
        crit: List[str] = []
        if after_uid: crit += ["UID", f"{after_uid + 1}:*"]
        if _imap_date(since): crit += ["SINCE", _imap_date(since)]
        if not crit: crit = ["ALL"]
        typ, data = conn.uid("SEARCH", None, *crit)
        if typ != "OK":
            raise RuntimeError(f"UID SEARCH failed: {data}")
        uids = [int(u) for u in (data[0] or b"").split()]
        uids = [u for u in uids if u > after_uid]
        if limit: uids = uids[:limit]
        if on_total: on_total(len(uids))
        host = self.src["host"]
        for i in range(0, len(uids), IMAP_BATCH):
            chunk = uids[i:i + IMAP_BATCH]
            typ, data = conn.uid("FETCH", ",".join(map(str, chunk)), "(UID INTERNALDATE BODY.PEEK[])")
            if typ != "OK":
                raise RuntimeError(f"UID FETCH failed: {data}")
            for item in data:
                if not isinstance(item, tuple) or len(item) < 2:
                    continue
                meta = item[0].decode("utf-8", "replace") if isinstance(item[0], bytes) else str(item[0])
                m = re.search(r"UID (\d+)", meta)
                uid = int(m.group(1)) if m else 0
                m2 = re.search(r'INTERNALDATE "([^"]+)"', meta)
                idate = m2.group(1) if m2 else None
                raw = item[1] if isinstance(item[1], bytes) else bytes(item[1])
                yield f"imap://{host}/{folder};uidvalidity={uidvalidity};uid={uid}", raw, idate, uid

    def idle_wait(self, folder: str, timeout: int = 1500) -> bool:
        """Block until the server reports new mail in `folder` (RFC 2177 IDLE) or timeout. Returns True if new mail."""
        conn = self.conn
        if "IDLE" not in getattr(self, "caps", ()):
            time.sleep(min(timeout, 60)); return True
        conn.select(_imap_quote(folder), readonly=True)
        tag = conn._new_tag()
        conn.send(tag + b" IDLE\r\n")
        resp = conn.readline()
        if not resp.startswith(b"+"):
            return True
        conn.sock.settimeout(timeout)
        got = False
        try:
            line = conn.readline()
            if b"EXISTS" in line or b"RECENT" in line:
                got = True
        except (socket.timeout, TimeoutError):
            pass
        finally:
            try:
                conn.sock.settimeout(30)
                conn.send(b"DONE\r\n")
                while True:
                    line = conn.readline()
                    if line.startswith(tag) or not line: break
            except Exception:
                pass
        return got


def test_source(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Connect, list folders, count messages since the configured date. Never stores anything."""
    if cfg.get("id") and not cfg.get("secret"):
        stored = get_source(cfg["id"], with_secret=True)
        if stored: cfg = {**stored, **{k: v for k, v in cfg.items() if v not in (None, "")}, "secret": stored["secret"]}
    t0 = time.time()
    try:
        with ImapSource(cfg) as s:
            caps = sorted(s.caps)
            folders = s.list_folders()
            want = cfg.get("folders") or ["INBOX"]
            if isinstance(want, str): want = [f.strip() for f in re.split(r"[,\n]", want) if f.strip()]
            counts = {f: s.count(f, cfg.get("since")) for f in want}
        return {"ok": True, "ms": int((time.time() - t0) * 1000), "capabilities": caps, "folders": [f["name"] for f in folders], "counts": counts,
                "idle": "IDLE" in caps, "total": sum(v for v in counts.values() if v > 0)}
    except Exception as e:
        return {"ok": False, "error": _friendly_imap_error(e), "ms": int((time.time() - t0) * 1000)}


def _friendly_imap_error(e: Exception) -> str:
    s = str(e)
    low = s.lower()
    if "application-specific password" in low or "app password" in low or "invalid credentials" in low or "authenticationfailed" in low or "authentication failed" in low:
        return ("Authentication failed. Gmail / Outlook.com require 2-Step Verification + an App Password (not your normal password); "
                "Microsoft 365 needs OAuth2 (choose auth = oauth2 and paste an access token). Detail: " + s)
    if "getaddrinfo" in low or "name or service not known" in low or "nodename" in low:
        return f"Host not found: {s}"
    if "timed out" in low:
        return f"Connection timed out — check host/port (993 for IMAPS) and that IMAP is enabled for the account. {s}"
    if "certificate" in low or "ssl" in low:
        return f"TLS problem: {s}"
    return s


# ------------------------------------------------------------------------------------------ file sources ----
def iter_container(path: str, display: str = "", on_total: Optional[Callable[[int], None]] = None) -> Iterator[Tuple[str, bytes]]:
    """Stream messages out of an .mbox / .zip / directory / single file. Yields (ref, raw).
    on_total(n) is called as soon as the number of messages in a container is known (progress bars / ETA)."""
    display = display or os.path.basename(path)
    low = path.lower()
    if os.path.isdir(path):
        for dp, _d, fns in os.walk(path):
            for fn in sorted(fns):
                if fn.lower().endswith((".eml", ".msg", ".txt", ".mbox", ".zip")):
                    yield from iter_container(os.path.join(dp, fn), os.path.relpath(os.path.join(dp, fn), path), on_total)
        return
    if low.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            infos = [i for i in z.infolist() if not i.is_dir() and i.file_size <= MAX_MSG_BYTES]
            if on_total: on_total(sum(1 for i in infos if i.filename.lower().endswith((".eml", ".msg", ".txt"))))
            for info in infos:
                name = info.filename
                nl = name.lower()
                if nl.endswith((".eml", ".msg", ".txt")):
                    yield f"file://{display}!{name}", z.read(info)
                elif nl.endswith(".mbox"):
                    tmp = os.path.join(DATA_DIR, f".tmp_{uuid.uuid4().hex}.mbox")
                    with z.open(info) as src, open(tmp, "wb") as dst:
                        while True:
                            b = src.read(1 << 20)
                            if not b: break
                            dst.write(b)
                    try:
                        yield from iter_container(tmp, f"{display}!{name}", on_total)
                    finally:
                        try: os.remove(tmp)
                        except OSError: pass
        return
    if low.endswith((".mbox", ".mbx")) or (not low.endswith((".eml", ".msg", ".txt")) and _looks_like_mbox(path)):
        mb = mailbox.mbox(path, create=False)
        try:
            if on_total: on_total(len(mb))              # mbox builds its table of contents on first access (one sequential scan)
            for i, key in enumerate(mb.iterkeys()):
                try:
                    raw = mb.get_bytes(key)
                except Exception as e:
                    log.warning("mbox %s message %d unreadable: %s", path, i, e); continue
                if raw and len(raw) <= MAX_MSG_BYTES:
                    yield f"file://{display}#msg{i + 1}", raw
        finally:
            mb.close()
        return
    raw = open(path, "rb").read()
    if raw[:5] == b"From " and raw.count(b"\nFrom ") > 0 and not low.endswith(".eml"):
        # mbox without extension
        mb = mailbox.mbox(path, create=False)
        if on_total: on_total(len(mb))
        for i, key in enumerate(mb.iterkeys()):
            yield f"file://{display}#msg{i + 1}", mb.get_bytes(key)
        mb.close(); return
    if low.endswith(".msg") and raw[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        conv = _msg_to_eml(raw)
        if conv: raw = conv
    if on_total: on_total(1)
    yield f"file://{display}", raw


def _looks_like_mbox(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(5) == b"From "
    except OSError:
        return False


def _msg_to_eml(raw: bytes) -> Optional[bytes]:
    """Best-effort Outlook .msg (OLE) → RFC 822 conversion using the transport headers stored in the file.
    Full fidelity needs the optional 'extract-msg' package; without it we still recover headers + text body."""
    try:
        import extract_msg  # type: ignore
        m = extract_msg.Message(io.BytesIO(raw))
        hdr = str(m.header) if m.header else ""
        body = m.body or ""
        if hdr and "Subject:" in hdr:
            return (hdr.rstrip() + "\r\n\r\n" + body).encode("utf-8", "replace")
    except Exception:
        pass
    # crude fallback: locate the UTF-16 transport-header property (PR_TRANSPORT_MESSAGE_HEADERS)
    try:
        txt = raw.decode("utf-16-le", "ignore")
        m = re.search(r"(Received:.*?\r?\n\r?\n)", txt, re.S)
        if m:
            return m.group(1).encode("utf-8", "replace") + b"\r\n(body not recoverable from .msg without extract-msg)\r\n"
    except Exception:
        pass
    return None


# ------------------------------------------------------------------------------------------------ jobs ----
class Job:
    def __init__(self, kind: str, label: str, actor: str, source_id: Optional[str] = None, detail: str = ""):
        self.id = "JOB-" + uuid.uuid4().hex[:8].upper()
        self.kind, self.label, self.actor, self.source_id, self.detail = kind, label, actor, source_id, detail
        self.mailbox: Optional[str] = None            # mail ID this job pulls from (IMAP); None → derived from the file ref
        self.status = "queued"
        self.total = self.fetched = self.analysed = self.duplicates = self.errors = self.malicious = self.suspicious = 0
        self.created_at, self.started_at, self.finished_at, self.error = _now(), None, None, None
        self.cancel = threading.Event()
        self.seq = 0
        self._dirty = time.time()
        self.t0 = time.time()
        self.lock = threading.Lock()
        self.queue: List[Tuple[float, str, str, str]] = []       # (provisional score, sha, case_id, ref) → enrichment phase
        self.enriched = 0; self.enrich_total = 0; self.phase = "queued"
        self.deep_min_score = DEEP_PASS_MIN_SCORE
        with _conn() as c:
            c.execute("INSERT INTO jobs(id,source_id,kind,label,status,created_at,actor,detail) VALUES (?,?,?,?,?,?,?,?)",
                      (self.id, source_id, kind, label, self.status, self.created_at, actor, detail))

    def to_dict(self) -> Dict[str, Any]:
        el = (time.time() - self.t0) if self.status in ("running", "fetching") else None
        rate = (self.analysed / el) if el and el > 0 and self.analysed else None
        remaining = max(0, self.total - self.analysed - self.duplicates - self.errors)
        if self.phase == "enrich" and el and self.enriched:
            rate = self.enriched / el; remaining = max(0, self.enrich_total - self.enriched)
        return {"id": self.id, "kind": self.kind, "label": self.label, "status": self.status, "phase": self.phase, "source_id": self.source_id, "actor": self.actor, "detail": self.detail,
                "total": self.total, "fetched": self.fetched, "analysed": self.analysed, "enriched": self.enriched, "enrich_total": self.enrich_total, "duplicates": self.duplicates, "errors": self.errors,
                "malicious": self.malicious, "suspicious": self.suspicious, "created_at": self.created_at, "started_at": self.started_at,
                "finished_at": self.finished_at, "error": self.error, "elapsed_s": int(el) if el else None,
                "rate_per_min": round(rate * 60, 1) if rate else None, "eta_s": int(remaining / rate) if rate and remaining else None}

    def persist(self, force: bool = False) -> None:
        if not force and time.time() - self._dirty < 1.0:
            return
        self._dirty = time.time()
        with _conn() as c:
            c.execute("""UPDATE jobs SET status=?, started_at=?, finished_at=?, total=?, fetched=?, analysed=?, duplicates=?, errors=?, malicious=?, suspicious=?, error=?, detail=?, enriched=?, phase=? WHERE id=?""",
                      (self.status, self.started_at, self.finished_at, self.total, self.fetched, self.analysed, self.duplicates, self.errors, self.malicious, self.suspicious, self.error, self.detail, self.enriched, self.phase, self.id))

    def emit(self, typ: str = "job", **extra) -> None:
        _publish({"type": typ, "job": self.to_dict(), "ts": time.time(), **extra})

    def item(self, ref: str, sha: str, status: str, case_id: str = None, score: float = None, label: str = None, error: str = None) -> None:
        with self.lock:
            self.seq += 1; seq = self.seq
        with _conn() as c:
            c.execute("INSERT OR REPLACE INTO job_items(job_id,seq,ref,sha256,case_id,status,score,label,error) VALUES (?,?,?,?,?,?,?,?,?)",
                      (self.id, seq, ref[:300], sha, case_id, status, score, label, (error or "")[:300]))

    def item_update(self, sha: str, status: str, score: float, label: str) -> None:
        with _conn() as c:
            c.execute("UPDATE job_items SET status=?, score=?, label=? WHERE job_id=? AND sha256=?", (status, score, label, self.id, sha))


_jobs: Dict[str, Job] = {}
_jobs_lock = threading.Lock()
_executor = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="mt-worker")


def list_jobs(limit: int = 30) -> List[Dict[str, Any]]:
    live = {j.id: j.to_dict() for j in _jobs.values()}
    with _conn() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()]
    return [live.get(r["id"], r) for r in rows]


def get_job(jid: str) -> Optional[Dict[str, Any]]:
    j = _jobs.get(jid)
    if j: d = j.to_dict()
    else:
        with _conn() as c:
            r = c.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
        if not r: return None
        d = dict(r)
    with _conn() as c:
        d["items"] = [dict(r) for r in c.execute("SELECT seq, ref, sha256, case_id, status, score, label, error FROM job_items WHERE job_id=? ORDER BY score DESC NULLS LAST, seq LIMIT 500", (jid,)).fetchall()]
    return d


def cancel_job(jid: str) -> bool:
    j = _jobs.get(jid)
    if not j: return False
    j.cancel.set(); return True


# ---------------------------------------------------------------------------------------- the pipeline ----
#  Phase 1 – TRIAGE : every message → dedupe → seal → analyse with live=False (no network, ~20-60 ms) → case saved
#                     with a provisional score. 1,000 emails ≈ under a minute; the dashboard fills up immediately.
#  Phase 2 – ENRICH : cases re-analysed with live=True (SPF/DKIM/DMARC DNS, GeoIP, RDAP, PTR, Tor), highest
#                     provisional score first, through cached & rate-limited resolvers. Skipped in offline mode.
def _triage_one(job: Job, ref: str, raw: bytes, source: str, unwrap: bool, org: Dict[str, Any]) -> None:
    if job.cancel.is_set():
        return
    note = None
    if unwrap:
        raw, note = unwrap_reported(raw)
    sha = hashlib.sha256(raw).hexdigest()
    existing = store.case_by_sha(sha)
    if existing:
        job.duplicates += 1
        job.item(ref, sha, "duplicate", existing["id"], existing["score"], existing.get("verdict"))
        store.log_custody(existing["id"], job.actor, "ingest-duplicate", f"seen again at {ref} (job {job.id})", sha, sha)
        job.persist(); job.emit()
        return
    try:
        result = analyze_email(raw, org, live=False)
        fname = ref.rsplit("/", 1)[-1][:120] if ref.startswith("imap://") else ref.split("!")[-1].split("#")[0][-120:]
        store.save_case(result, raw, fname, actor=job.actor, source=source, source_ref=ref + (f" | {note}" if note else ""), job_id=job.id, recluster_now=False, mailbox=job.mailbox)
        sc = result["score"]["score"]
        job.analysed += 1
        if sc >= 60: job.malicious += 1
        elif sc >= 35: job.suspicious += 1
        job.item(ref, sha, "triaged", result["id"], sc, result["score"]["label"])
        with job.lock:
            job.queue.append((sc, sha, result["id"], ref))
        _publish({"type": "alert" if sc >= 60 else "case", "case_id": result["id"], "score": sc, "label": result["score"]["label"], "subject": result["headers"]["subject"],
                  "sender": result["headers"]["from"]["address"], "threat": result["threat"]["primary"], "origin": (result["attribution"].get("origin_geo") or {}).get("country"),
                  "ts": time.time(), "job_id": job.id, "ref": ref, "depth": "triage"})
        if (job.analysed % (RECLUSTER_EVERY if job.analysed < 500 else RECLUSTER_EVERY * 10)) == 0:   # clustering is O(cases): back off on big jobs
            with _lock: store.recluster()
    except Exception as e:
        job.errors += 1
        job.item(ref, sha, "error", error=str(e))
        log.warning("job %s: %s failed: %s", job.id, ref, e)
    job.persist(); job.emit()


def _enrich_one(job: Job, sc0: float, sha: str, cid: str, ref: str, org: Dict[str, Any]) -> None:
    if job.cancel.is_set():
        return
    p = store.evidence_path(sha)
    if not p:
        return
    try:
        raw = open(p, "rb").read()
        result = analyze_email(raw, org, live=True)
        fname = ref.rsplit("/", 1)[-1][:120] if ref.startswith("imap://") else ref.split("!")[-1].split("#")[0][-120:]
        store.save_case(result, raw, fname, actor=job.actor, source=None, source_ref=None, job_id=None, recluster_now=False, custody_action="enrich")
        sc = result["score"]["score"]
        if sc0 >= 60: job.malicious -= 1
        elif sc0 >= 35: job.suspicious -= 1
        if sc >= 60: job.malicious += 1
        elif sc >= 35: job.suspicious += 1
        job.enriched += 1
        job.item_update(sha, "analysed", sc, result["score"]["label"])
        if sc >= 60 and sc0 < 60:
            _publish({"type": "alert", "case_id": result["id"], "score": sc, "label": result["score"]["label"], "subject": result["headers"]["subject"],
                      "sender": result["headers"]["from"]["address"], "threat": result["threat"]["primary"], "origin": (result["attribution"].get("origin_geo") or {}).get("country"),
                      "ts": time.time(), "job_id": job.id, "ref": ref, "depth": "full"})
        else:
            _publish({"type": "enriched", "case_id": result["id"], "score": sc, "label": result["score"]["label"], "ts": time.time(), "job_id": job.id})
    except Exception as e:
        job.errors += 1
        log.warning("job %s: enrichment of %s failed: %s", job.id, cid, e)
    job.persist(); job.emit()


def _finish(job: Job, status: str = "done") -> None:
    try:
        with _lock: store.recluster()
    except Exception as e:
        log.warning("recluster failed: %s", e)
    intel.flush_cache()
    job.status = status if not job.cancel.is_set() else "cancelled"
    job.phase = "finished"
    job.finished_at = _now()
    job.persist(force=True)
    job.emit("job-done")
    log.info("job %s %s: total=%d analysed=%d enriched=%d dup=%d err=%d malicious=%d in %.1fs", job.id, job.status, job.total, job.analysed, job.enriched,
             job.duplicates, job.errors, job.malicious, time.time() - job.t0)


def _run_stream(job: Job, stream: Iterable[Tuple[str, bytes]], source: str, unwrap: bool) -> None:
    """Feed a (ref, raw) iterator through the worker pool (bounded in-flight, so a 50k-message mbox never sits in RAM),
    then run the enrichment phase worst-first."""
    org = load_org_profile()
    job.status = "running"; job.phase = "triage"; job.started_at = _now(); job.t0 = time.time(); job.persist(force=True); job.emit()
    inflight: List = []
    try:
        for ref, raw in stream:
            if job.cancel.is_set():
                break
            job.fetched += 1
            if len(raw) > MAX_MSG_BYTES:
                job.errors += 1; job.item(ref, "", "error", error="message larger than 25 MB"); continue
            inflight.append(_executor.submit(_triage_one, job, ref, raw, source, unwrap, org))
            if len(inflight) >= WORKERS * 4:
                inflight[0].result(); inflight.pop(0)
                inflight = [f for f in inflight if not f.done()]
        for f in inflight: f.result()
        inflight = []
        if job.total < job.fetched: job.total = job.fetched
        # ---- phase 2: enrichment, worst first ----
        if not intel.OFFLINE and not job.cancel.is_set() and job.queue:
            with _lock: store.recluster()
            job.phase = "enrich"; job.emit()
            todo = sorted(job.queue, key=lambda x: -x[0])
            todo = [t for t in todo if t[0] >= job.deep_min_score]
            job.enrich_total = len(todo)
            for i, (sc0, sha, cid, ref) in enumerate(todo):
                if job.cancel.is_set(): break
                inflight.append(_executor.submit(_enrich_one, job, sc0, sha, cid, ref, org))
                if len(inflight) >= WORKERS * 2:
                    inflight[0].result(); inflight.pop(0)
                    inflight = [f for f in inflight if not f.done()]
                if i and i % (RECLUSTER_EVERY if len(todo) < 500 else RECLUSTER_EVERY * 10) == 0:
                    with _lock: store.recluster()
            for f in inflight: f.result()
        _finish(job)
    except Exception as e:
        for f in inflight:
            try: f.result()
            except Exception: pass
        job.error = str(e)
        log.exception("job %s failed", job.id)
        _finish(job, "failed")
    finally:
        _jobs.pop(job.id, None)


def start_file_job(paths: List[str], actor: str, label: str = "", unwrap: bool = True, cleanup: bool = False, deep_min_score: float = None,
                   names: Optional[List[str]] = None) -> Dict[str, Any]:
    """Bulk import from .mbox / .zip / folder / .eml paths (already on this machine). `names` = user-facing names for uploads."""
    names = names or [os.path.basename(p) for p in paths]
    label = label or (", ".join(names) if len(names) <= 3 else f"{names[0]} + {len(names) - 1} more")[:120]
    job = Job("import", label, actor, detail=json.dumps({"paths": names}))
    if deep_min_score is not None: job.deep_min_score = float(deep_min_score)
    _jobs[job.id] = job

    def _tot(n):
        job.total += n; job.persist(force=True); job.emit()

    def stream():
        try:
            for p, nm in zip(paths, names):
                yield from iter_container(p, nm, _tot)
        finally:
            if cleanup:
                for p in paths:
                    try: os.remove(p)
                    except OSError: pass

    threading.Thread(target=_run_stream, args=(job, stream(), "import", unwrap), daemon=True, name=f"job-{job.id}").start()
    return job.to_dict()


def start_imap_job(sid: str, actor: str, mode: str = "backfill", limit: int = 0, deep_min_score: float = None) -> Dict[str, Any]:
    """Fetch from an IMAP source: backfill (since date, all folders) or incremental (UID > last seen)."""
    src = get_source(sid, with_secret=True)
    if not src: raise ValueError("source not found")
    with _jobs_lock:
        if any(j.source_id == sid for j in _jobs.values()): raise ValueError("a job for this source is already running")
        job = Job("imap", f"{src['name']} ({mode})", actor, source_id=sid, detail=json.dumps({"host": src["host"], "folders": src["folders"], "mode": mode}))
        job.mailbox = (src.get("username") or src.get("name") or "").strip()[:200]
        if deep_min_score is not None: job.deep_min_score = float(deep_min_score)
        _jobs[job.id] = job

    def stream():
        state = dict(src.get("state") or {})
        with ImapSource(src) as s:
            for folder in src["folders"] or ["INBOX"]:
                after = int(state.get(f"last_uid:{folder}", 0)) if mode == "incremental" else 0
                job.status = "fetching"; job.emit()
                last = after
                def _tot(n, _f=folder):
                    job.total += n; job.persist(force=True); job.emit()
                for ref, raw, idate, uid in s.iter_messages(folder, src.get("since"), after_uid=after, limit=limit, on_total=_tot):
                    job.status = "running"
                    yield ref, raw
                    last = max(last, uid)
                    if job.cancel.is_set():
                        break
                state[f"last_uid:{folder}"] = last
                _update_source(sid, state=json.dumps(state), last_run=_now(), last_error=None)
                if job.cancel.is_set():
                    break

    def run():
        try:
            _run_stream(job, stream(), "imap", bool(src.get("unwrap", True)))
            if job.error:                       # surfaced by the job itself (connect/auth/read failure)
                _update_source(sid, last_error=str(job.error)[:400], last_run=_now())
        except Exception as e:
            _update_source(sid, last_error=str(e)[:400], last_run=_now())
    threading.Thread(target=run, daemon=True, name=f"job-{job.id}").start()
    return job.to_dict()


# ---------------------------------------------------------------------------------------------- monitor ----
class IdleWatcher(threading.Thread):
    """One long-lived read-only connection per mode='idle' source: sits in IMAP IDLE (RFC 2177) and, whenever the server
    announces new mail, runs an incremental fetch. Falls back to a 60 s poll if the server lacks IDLE. Reconnects on error."""

    def __init__(self, sid: str):
        super().__init__(daemon=True, name=f"mt-idle-{sid}")
        self.sid = sid; self.stop_evt = threading.Event(); self.last_error: Optional[str] = None
        self._src: Optional[ImapSource] = None

    def stop(self):
        """Set the stop flag AND shut the socket so a thread parked in IDLE wakes up immediately."""
        self.stop_evt.set()
        s = self._src
        if s and s.conn is not None:
            try: s.conn.sock.shutdown(socket.SHUT_RDWR)
            except Exception: pass

    def run(self):
        backoff = 5
        while not self.stop_evt.is_set():
            src = get_source(self.sid, with_secret=True)
            if not src or not src.get("enabled") or src.get("mode") != "idle":
                return
            folder = (src.get("folders") or ["INBOX"])[0]
            try:
                if not any(k.startswith("last_uid:") for k in (src.get("state") or {})):
                    self._run_and_wait("backfill")
                with ImapSource(src) as s:
                    self._src = s
                    backoff = 5
                    if src.get("last_error"):
                        _update_source(self.sid, last_error=None)
                    while not self.stop_evt.is_set():
                        cur = get_source(self.sid)
                        if not cur or not cur.get("enabled") or cur.get("mode") != "idle":
                            return
                        got = s.idle_wait(folder, timeout=1500)
                        if self.stop_evt.is_set():
                            return
                        if got:
                            self._run_and_wait("incremental")
                            s.conn.select(_imap_quote(folder), readonly=True)
            except Exception as e:
                if self.stop_evt.is_set():
                    return
                self.last_error = str(e)
                _update_source(self.sid, last_error=f"IDLE connection lost ({e}); reconnecting in {backoff}s")
                self.stop_evt.wait(backoff); backoff = min(backoff * 2, 300)
            finally:
                self._src = None

    def _run_and_wait(self, mode: str):
        try:
            j = start_imap_job(self.sid, actor="monitor", mode=mode)
        except ValueError:
            return
        while j["id"] in _jobs and not self.stop_evt.is_set():
            time.sleep(1)


class Monitor(threading.Thread):
    """Background scheduler: every source with mode='monitor' is polled every interval_min minutes (incremental UIDs);
    mode='idle' sources get a dedicated IdleWatcher connection that wakes on the server's IDLE notification."""

    def __init__(self):
        super().__init__(daemon=True, name="mt-monitor")
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._last: Dict[str, float] = {}
        self._idle: Dict[str, IdleWatcher] = {}
        self.enabled = True
        self.started_at: Optional[str] = None
        self.last_tick: Optional[str] = None
        self.last_catchup: Optional[str] = None

    def wake(self): self._wake.set()
    def stop(self): self._stop.set(); self._wake.set()

    def set_enabled(self, flag: bool) -> None:
        self.enabled = bool(flag)
        if flag: self.wake()
        else:                                   # stop every IDLE connection; the loop then idles
            for sid, w in list(self._idle.items()):
                w.stop(); w.join(timeout=5); self._idle.pop(sid, None)

    def catch_up(self, actor: str = "monitor") -> List[str]:
        """Startup catch-up: scan every SELECTED account once, right now, so messages that arrived
        while MailTrace AI was closed are analysed before the user does anything.
        Uses the stored UID checkpoint, so nothing already processed is fetched again."""
        started = []
        for src in list_sources():
            if not src.get("enabled") or src.get("mode") not in ("monitor", "idle"):
                continue
            if src.get("mode") == "idle":
                continue                         # IDLE watchers backfill themselves on connect
            if any(j.source_id == src["id"] for j in _jobs.values()):
                continue
            first = not src.get("state") or not any(k.startswith("last_uid:") for k in src["state"])
            try:
                started.append(start_imap_job(src["id"], actor=actor, mode="backfill" if first else "incremental")["id"])
            except Exception as e:
                _update_source(src["id"], last_error=str(e))
            self._last[src["id"]] = time.time()
        self.last_catchup = _now()
        return started

    def run(self):
        time.sleep(3)
        self.started_at = _now()
        try:
            self.catch_up()                      # "check mail that arrived since the last checkpoint"
        except Exception as e:
            log.warning("startup catch-up failed: %s", e)
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as e:
                log.warning("monitor tick failed: %s", e)
            self._wake.wait(15); self._wake.clear()

    def _tick(self):
        if not self.enabled: return
        self.last_tick = _now()
        srcs = list_sources()
        # IDLE watchers: start for idle sources, stop for the rest
        want = {s["id"] for s in srcs if s.get("enabled") and s.get("mode") == "idle"}
        for sid, w in list(self._idle.items()):
            if sid not in want or not w.is_alive():
                w.stop(); w.join(timeout=5); self._idle.pop(sid, None)
        for sid in want - set(self._idle):
            w = IdleWatcher(sid); self._idle[sid] = w; w.start()
        for src in srcs:
            if not src.get("enabled") or src.get("mode") != "monitor": continue
            if any(j.source_id == src["id"] for j in _jobs.values()): continue
            due = self._last.get(src["id"], 0) + max(1, int(src.get("interval_min") or 5)) * 60
            if time.time() < due: continue
            self._last[src["id"]] = time.time()
            first = not src.get("state") or not any(k.startswith("last_uid:") for k in src["state"])
            try:
                start_imap_job(src["id"], actor="monitor", mode="backfill" if first else "incremental")
            except Exception as e:
                _update_source(src["id"], last_error=str(e), last_run=_now())


_monitor = Monitor()


def monitor_status() -> Dict[str, Any]:
    """Everything the UI needs to show monitoring state — all of it read from live engine state."""
    jobs = [j.to_dict() for j in _jobs.values()]
    out = []
    for s in list_sources():
        st = s.get("state") or {}
        uids = {k.split(":", 1)[1]: int(v) for k, v in st.items() if k.startswith("last_uid:")}
        active = next((j["id"] for j in jobs if j.get("source_id") == s["id"] and j.get("status") not in ("done", "error", "cancelled")), None)
        due_in = None
        if s.get("enabled") and s.get("mode") == "monitor":
            interval = max(1, int(s.get("interval_min") or 5)) * 60
            due_in = max(0, int(_monitor._last.get(s["id"], 0) + interval - time.time()))
        out.append({
            "id": s["id"], "name": s["name"], "username": s.get("username"), "host": s.get("host"),
            "port": s.get("port"), "folders": s.get("folders") or ["INBOX"], "mode": s.get("mode"),
            "enabled": bool(s.get("enabled")), "interval_min": s.get("interval_min"),
            "last_run": s.get("last_run"), "last_error": s.get("last_error"), "since": s.get("since"),
            "checkpoints": uids, "selected": bool(s.get("enabled")) and s.get("mode") in ("monitor", "idle"),
            "has_secret": s.get("has_secret"), "active_job": active, "due_in_s": due_in,
            "watching": s["id"] in [sid for sid, w in _monitor._idle.items() if w.is_alive()],
        })
    selected = [x for x in out if x["selected"]]
    return {
        "running": _monitor.is_alive(), "enabled": _monitor.enabled,
        "started_at": _monitor.started_at, "last_tick": _monitor.last_tick, "last_catchup": _monitor.last_catchup,
        "accounts": len(out), "selected": len(selected),
        "sources": out, "active_jobs": jobs,
        "idle_watchers": [sid for sid, w in _monitor._idle.items() if w.is_alive()],
    }


def scan_now(sid: Optional[str] = None, actor: str = "analyst", mode: str = "incremental") -> List[Dict[str, Any]]:
    """Scan the selected account(s) on demand using the stored checkpoint (no duplicates)."""
    out = []
    for src in list_sources():
        if not src.get("enabled") or src.get("mode") not in ("monitor", "idle", "once"):
            continue
        if sid and src["id"] != sid:
            continue
        if any(j.source_id == src["id"] for j in _jobs.values()):
            out.append({"source_id": src["id"], "error": "a scan for this account is already running"})
            continue
        first = not src.get("state") or not any(k.startswith("last_uid:") for k in src["state"])
        try:
            out.append(start_imap_job(src["id"], actor=actor, mode="backfill" if first else mode))
        except Exception as e:
            out.append({"source_id": src["id"], "error": str(e)})
        _monitor._last[src["id"]] = time.time()
    if not out:
        out = [{"error": "no account is selected for monitoring"}]
    return out


def set_monitor_enabled(flag: bool) -> bool:
    _monitor.set_enabled(flag)
    return _monitor.enabled


def start_monitor() -> None:
    if not _monitor.is_alive():
        try: _monitor.start()
        except RuntimeError: pass


def status() -> Dict[str, Any]:
    return {"workers": WORKERS, "active_jobs": [j.to_dict() for j in _jobs.values()], "monitor": _monitor.is_alive(), "sources": len(list_sources()),
            "idle_watchers": [sid for sid, w in _monitor._idle.items() if w.is_alive()]}


init()
