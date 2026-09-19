"""Notification history for MailTrace AI.

Every entry is derived from a REAL event that already happened (an analysed email, a
finished scan job). Nothing here invents counts: summaries are counted from the cases
table by job id, single-email alerts carry the score the analysis engine produced.

Persisted in the same SQLite database as the cases so history survives a restart and
the desktop/web front-ends see identical data.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from analyzer.common import DATA_DIR

DB_PATH = os.path.join(DATA_DIR, "mailtrace.db")
log = logging.getLogger("uvicorn.error")
_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _parse_ts(ts: str) -> float:
    try:
        return time.mktime(time.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S"))
    except Exception:
        return 0.0


def init() -> None:
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS notifications(
            id TEXT PRIMARY KEY,
            ts TEXT,
            kind TEXT,            -- threat | scan | info
            severity TEXT,        -- critical | high | medium | low | ok
            title TEXT,
            body TEXT,
            case_id TEXT,
            account TEXT,
            counts TEXT,          -- json: {malicious, suspicious, clean, analysed}
            read INTEGER DEFAULT 0
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_notif_ts ON notifications(ts)")


def _row(d: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": d["id"], "ts": d["ts"], "kind": d["kind"], "severity": d["severity"],
        "title": d["title"], "body": d["body"], "case_id": d["case_id"], "account": d["account"],
        "counts": json.loads(d["counts"] or "{}"), "read": bool(d["read"]),
    }


def add(kind: str, title: str, body: str = "", severity: str = "info", case_id: Optional[str] = None,
        account: Optional[str] = None, counts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    # a mailbox that stays unreachable retries every interval — collapse repeats of the SAME error
    # for 20 minutes instead of flooding the history with identical entries
    if kind in ("error", "scan"):
        with _conn() as c:
            dup = c.execute("""SELECT id FROM notifications WHERE kind=? AND account=? AND body=? AND read=0
                               ORDER BY ts DESC, rowid DESC LIMIT 1""", (kind, (account or "")[:200], (body or "")[:400])).fetchone()
            if dup:
                recent = c.execute("""SELECT ts FROM notifications WHERE id=?""", (dup["id"],)).fetchone()
                if recent and (time.time() - _parse_ts(recent["ts"])) < 1200:
                    c.execute("UPDATE notifications SET ts=? WHERE id=?", (_now(), dup["id"]))
                    return {**_row(c.execute("SELECT * FROM notifications WHERE id=?", (dup["id"],)).fetchone())}
    nid = "NTF-" + uuid.uuid4().hex[:8].upper()
    row = {
        "id": nid, "ts": _now(), "kind": kind, "severity": severity, "title": title[:200],
        "body": (body or "")[:400], "case_id": case_id, "account": (account or "")[:200],
        "counts": json.dumps(counts or {}), "read": 0,
    }
    with _lock, _conn() as c:
        c.execute("""INSERT INTO notifications(id,ts,kind,severity,title,body,case_id,account,counts,read)
                     VALUES(:id,:ts,:kind,:severity,:title,:body,:case_id,:account,:counts,:read)""", row)
    return {**row, "counts": counts or {}, "read": False}


def list_notifications(limit: int = 60, unread_only: bool = False) -> List[Dict[str, Any]]:
    with _conn() as c:
        q = "SELECT * FROM notifications"
        if unread_only:
            q += " WHERE read=0"
        q += " ORDER BY ts DESC, rowid DESC LIMIT ?"
        return [_row(r) for r in c.execute(q, (int(limit),)).fetchall()]


def unread_count() -> int:
    with _conn() as c:
        return int(c.execute("SELECT COUNT(*) n FROM notifications WHERE read=0").fetchone()["n"])


def mark_read(nid: Optional[str] = None, all: bool = False) -> int:
    with _lock, _conn() as c:
        if all:
            cur = c.execute("UPDATE notifications SET read=1 WHERE read=0")
        elif nid:
            cur = c.execute("UPDATE notifications SET read=1 WHERE id=?", (nid,))
        else:
            return 0
        return int(cur.rowcount or 0)


def clear(keep: int = 200) -> int:
    """Trim very old history (keeps the newest `keep` rows)."""
    with _lock, _conn() as c:
        cur = c.execute("""DELETE FROM notifications WHERE id NOT IN
                           (SELECT id FROM notifications ORDER BY ts DESC, rowid DESC LIMIT ?)""", (int(keep),))
        return int(cur.rowcount or 0)


def case_exists(cid: str) -> bool:
    with _conn() as c:
        return c.execute("SELECT 1 FROM cases WHERE id=?", (cid,)).fetchone() is not None


def job_counts(job_id: str) -> Dict[str, int]:
    """Real verdict counts for a finished job, counted from the stored cases."""
    out = {"malicious": 0, "suspicious": 0, "clean": 0, "analysed": 0}
    if not job_id:
        return out
    with _conn() as c:
        for r in c.execute("SELECT verdict, COUNT(*) n FROM cases WHERE job_id=? GROUP BY verdict", (job_id,)).fetchall():
            v, n = (r["verdict"] or ""), int(r["n"])
            out["analysed"] += n
            if v in ("malicious", "likely_malicious"):
                out["malicious"] += n
            elif v == "suspicious":
                out["suspicious"] += n
            else:
                out["clean"] += n
    return out


def counts_severity(counts: Dict[str, int]) -> str:
    if counts.get("malicious"):
        return "critical"
    if counts.get("suspicious"):
        return "medium"
    return "ok"


def score_severity(score: float) -> str:
    s = float(score or 0)
    return "critical" if s >= 80 else "high" if s >= 60 else "medium" if s >= 35 else "low" if s >= 15 else "ok"


def consume(evt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Turn a published engine event into a persisted notification (idempotent-ish, never fakes data)."""
    try:
        t = evt.get("type")
        if t == "alert":
            score = float(evt.get("score") or 0)
            return add("threat",
                       f"{evt.get('label') or 'High-risk email'} — {round(score)}/100",
                       f"{evt.get('subject') or '(no subject)'} · from {evt.get('sender') or 'unknown sender'}",
                       severity=score_severity(score), case_id=evt.get("case_id"),
                       account=evt.get("sender") or "", counts={"score": round(score, 1), "label": evt.get("label")})
        if t == "job-done":
            job = evt.get("job") or {}
            if job.get("kind") != "imap":
                return None
            if job.get("status") in ("failed", "error") or job.get("error"):
                return add("error", "Mailbox scan failed",
                           f"{(job.get('label') or 'account')}: {str(job.get('error') or 'unknown error')[:200]}",
                           severity="high", account=(job.get("mailbox") or ""))
            analysed = int(job.get("analysed") or 0)
            if analysed <= 0:
                return None
            if analysed == 1:
                return None                      # a single message already produced its own alert
            counts = job_counts(job.get("id"))
            if not counts["analysed"]:
                counts = {"malicious": int(job.get("malicious") or 0), "suspicious": int(job.get("suspicious") or 0),
                          "clean": max(0, analysed - int(job.get("malicious") or 0) - int(job.get("suspicious") or 0)),
                          "analysed": analysed}
            account = job.get("mailbox") or (job.get("label") or "").split(" (")[0]
            body = (f"{counts['malicious']} malicious · {counts['suspicious']} suspicious · {counts['clean']} clean"
                    f" · {counts['analysed']} analysed")
            return add("scan", "New email analysis completed", body, severity=counts_severity(counts),
                       account=account, counts=counts)
    except Exception as e:                        # never let the UI layer break the pipeline
        log.warning("notification hook failed: %s", e)
    return None


init()
