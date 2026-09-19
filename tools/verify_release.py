#!/usr/bin/env python3
"""Verify a MailTrace AI release tree (or zip) is complete, clean and runnable.

    python3 tools/verify_release.py <extracted-dir>
    python3 tools/verify_release.py --zip MailTrace-AI-FINAL-PRODUCTION.zip

Checks: required files, packaged runtime, offline frontend (no CDN), no runtime
data or secrets, no build junk. Exits 1 if any check fails.
"""
from __future__ import annotations

import os
import re
import shutil
import struct
import sys
import tempfile
import zipfile

APP = os.path.join("MAILWORKING", "MailTrace AI")

REQUIRED_FILES = [
    "README.md",
    "RUN.txt",
    "Unblock-Windows.bat",
    "Unblock-Windows.ps1",
    "Start-MailTrace-AI.bat",
    "Start-Engine-and-Open.bat",
    os.path.join(APP, "MailTrace AI.exe"),
    os.path.join(APP, "Unblock-Windows.bat"),
    os.path.join(APP, "Start-MailTrace-AI.bat"),
    os.path.join(APP, "_internal", "python312.dll"),
    os.path.join(APP, "_internal", "frontend", "index.html"),
    os.path.join(APP, "_internal", "frontend", "app.js"),
    os.path.join(APP, "_internal", "frontend", "app.css"),
    os.path.join(APP, "_internal", "frontend", "motion.css"),
    os.path.join(APP, "_internal", "frontend", "vendor", "three.min.js"),
    os.path.join(APP, "_internal", "frontend", "data", "world.js"),
    os.path.join(APP, "_internal", "frontend", "data", "centroids.js"),
    os.path.join(APP, "_internal", "backend", "main.py"),
    os.path.join(APP, "_internal", "backend", "ingest.py"),
    os.path.join(APP, "_internal", "backend", "store.py"),
    os.path.join(APP, "_internal", "backend", "report.py"),
    os.path.join(APP, "_internal", "backend", "notify.py"),
    os.path.join(APP, "_internal", "backend", "analyzer", "engine.py"),
    os.path.join(APP, "_internal", "backend", "analyzer", "header_forensics.py"),
    os.path.join(APP, "_internal", "backend", "analyzer", "nlp_portable.py"),
    os.path.join(APP, "_internal", "backend", "models", "phish_nlp_portable.json.gz"),
    os.path.join(APP, "_internal", "backend", "config", "org_profile.json"),
    os.path.join(APP, "_internal", "backend", "data", "geo_seed.json"),
    os.path.join("MAILWORKING", "docs", "INGESTION.md"),
    os.path.join("MAILWORKING", "docs", "MailTrace-AI_Solution.docx"),
    os.path.join("MAILWORKING", "demo", "demo_mailbox_300.mbox"),
    os.path.join("tools", "test_api.py"),
    os.path.join("tools", "test_motion.js"),
    os.path.join("tools", "README.md"),
    os.path.join("tools", "build_release.sh"),
    "Check-Runtime.bat",
    "Check-Runtime.ps1",
]

REQUIRED_DIRS = [
    os.path.join(APP, "_internal", "frontend", "lib"),
    os.path.join(APP, "_internal", "backend", "samples"),
]

FRONTEND_LIBS = ["console.js", "fx.js", "geo.js", "globe.js", "graph.js",
                 "motion.js", "pipeline.js", "snake.js"]

FORBIDDEN_PATH_PARTS = ["__pycache__", ".git"]
FORBIDDEN_SUFFIXES = (".pyc",)
FORBIDDEN_NAMES = {
    "mailtrace.db", ".mailtrace.key", "intel_cache.json",
    "MailTrace-AI-FINAL-PRODUCTION.zip", "MAILWORKING.zip",
}
FORBIDDEN_DIRS = {"evidence", "uploads"}

# real credentials / keys must never be shipped
SECRET_RE = re.compile(
    r"(?i)\b(app[_-]?password|passwd|smtp[_-]?pass|api[_-]?key|secret[_-]?key|"
    r"private[_-]?key|bearer\s+[A-Za-z0-9._-]{20,}|AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_\-]{30,})\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']"
)
CDN_RE = re.compile(r"(?i)<\s*(script|link)[^>]+(src|href)\s*=\s*[\"']https?://")


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        yield dirpath, dirnames, filenames


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2
    tmp = None
    if args[0] == "--zip":
        zp = args[1]
        with zipfile.ZipFile(zp) as z:
            bad = z.testzip()
            if bad:
                print(f"FAIL corrupt entry in zip: {bad}")
                return 1
            tmp = tempfile.mkdtemp(prefix="mt-verify-")
            z.extractall(tmp)
        root = tmp
        print(f"extracted {zp} -> {root}")
    else:
        root = args[0]

    results = []

    def check(ok, label, detail=""):
        results.append((bool(ok), label, detail))

    try:
        for rel in REQUIRED_FILES:
            check(os.path.isfile(os.path.join(root, rel)), f"file {rel}")
        for rel in REQUIRED_DIRS:
            check(os.path.isdir(os.path.join(root, rel)), f"dir  {rel}")

        libdir = os.path.join(root, APP, "_internal", "frontend", "lib")
        for name in FRONTEND_LIBS:
            check(os.path.isfile(os.path.join(libdir, name)), f"frontend lib/{name}")

        sdir = os.path.join(root, APP, "_internal", "backend", "samples")
        samples = [f for f in os.listdir(sdir) if f.endswith(".eml")] if os.path.isdir(sdir) else []
        check(len(samples) >= 10, f"sample corpus ({len(samples)} .eml files)")

        fe = os.path.join(root, APP, "_internal", "frontend")
        cdn_hits = []
        secret_hits = []
        junk = []
        for dirpath, dirnames, filenames in walk(root):
            rel = os.path.relpath(dirpath, root)
            for d in list(dirnames):
                if d in FORBIDDEN_PATH_PARTS or d in FORBIDDEN_DIRS:
                    junk.append(os.path.join(rel, d))
            for f in filenames:
                p = os.path.join(dirpath, f)
                if f in FORBIDDEN_NAMES or f.endswith(FORBIDDEN_SUFFIXES):
                    junk.append(os.path.relpath(p, root))
                if f.endswith((".html", ".js", ".css")) and os.path.dirname(p) == fe or \
                        f.endswith((".html", ".js", ".css")) and rel.startswith(os.path.join(APP, "_internal", "frontend")):
                    try:
                        text = open(p, encoding="utf-8", errors="ignore").read()
                    except OSError:
                        continue
                    for line in CDN_RE.findall(text):
                        cdn_hits.append(f"{os.path.relpath(p, root)}: {line}")
                if f.endswith((".py", ".js", ".json", ".html", ".css", ".txt", ".md", ".bat", ".ps1")):
                    if os.path.getsize(p) > 4_000_000:
                        continue
                    try:
                        text = open(p, encoding="utf-8", errors="ignore").read()
                    except OSError:
                        continue
                    for m in SECRET_RE.finditer(text):
                        secret_hits.append(f"{os.path.relpath(p, root)}: {m.group(0)[:48]}")

        check(not junk, "no build junk / runtime data / nested archives", "; ".join(junk[:5]))
        check(not cdn_hits, "frontend is fully offline (no CDN tags)", "; ".join(cdn_hits[:5]))
        check(not secret_hits, "no hardcoded credentials or keys", "; ".join(secret_hits[:5]))

        exe = os.path.join(root, APP, "MailTrace AI.exe")
        check(os.path.getsize(exe) > 5_000_000, "MailTrace AI.exe is a real binary")

        # ----- packaged Python runtime: what the PyInstaller bootloader needs -----
        internal = os.path.join(root, APP, "_internal")
        cookie = b"MEI\014\013\012\013\016"
        toc_info = None
        try:
            with open(exe, "rb") as fh:
                blob = fh.read()
            at = blob.rfind(cookie)
            magic, pkg, toc, toclen, pyvers, pylib = struct.unpack("!8sIIII64s", blob[at:at + 88])
            pkgstart = len(blob) - pkg
            names, p = [], 0
            chunk = blob[pkgstart + toc: pkgstart + toc + toclen]
            while p + 18 <= len(chunk):
                sl = struct.unpack("!i", chunk[p:p + 4])[0]
                typ = chunk[p + 17:p + 18]
                names.append((typ.decode("latin1"), chunk[p + 18:p + sl].split(b"\0")[0].decode("utf-8", "replace")))
                p += sl
            toc_info = {
                "pyvers": pyvers,
                "pylib": pylib.rstrip(b"\0").decode(),
                "contents": [n for t, n in names if t == "o" and n.startswith("pyi-contents-directory ")],
                "pyz": [n for t, n in names if t == "z"],
                "scripts": [n for t, n in names if t == "s"],
            }
        except Exception as exc:                                   # unreadable exe → reported below
            toc_info = {"error": str(exc)}

        check(bool(toc_info) and "error" not in toc_info, "EXE carries a readable PyInstaller archive",
              toc_info.get("error", "") if toc_info else "no TOC")
        if toc_info and "error" not in toc_info:
            check(toc_info["pyvers"] == 312, "embedded Python version is 3.12", str(toc_info["pyvers"]))
            check(bool(toc_info["pyz"]), "frozen module archive (PYZ) is present", str(toc_info["pyz"]))
            check("mailtrace_desktop" in toc_info["scripts"], "launcher script is bundled",
                  ", ".join(toc_info["scripts"]))
            contents = toc_info["contents"][0].split()[-1] if toc_info["contents"] else "_internal"
            check(os.path.isdir(os.path.join(root, APP, contents)),
                  "contents directory '%s' exists" % contents)
            check(os.path.isfile(os.path.join(internal, toc_info["pylib"])),
                  "interpreter %s is in _internal" % toc_info["pylib"])

        bl = os.path.join(internal, "base_library.zip")
        bl_ok, bl_detail = False, "missing"
        if os.path.isfile(bl) and zipfile.is_zipfile(bl):
            with zipfile.ZipFile(bl) as z:
                names_in = z.namelist()
                bad = z.testzip()
            core = [m for m in ("codecs.pyc", "os.pyc", "io.pyc", "encodings/__init__.pyc") if m in names_in]
            bl_ok = bad is None and len(names_in) > 50 and len(core) >= 2
            bl_detail = "%d modules, core: %s" % (len(names_in), ", ".join(core) or "MISSING")
        check(bl_ok, "base_library.zip: Python core modules (missing = 'Failed to start embedded python interpreter!')",
              bl_detail)

        pyd = sorted(f for f in os.listdir(internal) if f.endswith(".pyd")) if os.path.isdir(internal) else []
        need = {"_socket.pyd", "_ssl.pyd", "select.pyd", "_ctypes.pyd", "unicodedata.pyd"}
        check(len(pyd) >= 15, "compiled stdlib extension modules (.pyd) shipped: %d" % len(pyd))
        check(need.issubset(set(pyd)), "required extension modules present",
              "missing: " + ", ".join(sorted(need - set(pyd))))
        for dll in ("python312.dll", "sqlite3.dll", "VCRUNTIME140.dll"):
            check(os.path.isfile(os.path.join(internal, dll)), "runtime %s" % dll)
        for helper in ("Unblock-Windows.bat", "Start-MailTrace-AI.bat", "Start-Engine-and-Open.bat",
                       "Check-Runtime.bat", "Check-Runtime.ps1"):
            check(os.path.isfile(os.path.join(root, APP, helper)), "helper next to the exe: %s" % helper)

        failures = [r for r in results if not r[0]]
        for ok, label, detail in results:
            print(f"  {'PASS' if ok else 'FAIL'}  {label}{('  <- ' + detail) if (detail and not ok) else ''}")
        print(f"\n{'PASS' if not failures else 'FAIL'} {len(results) - len(failures)}/{len(results)} checks")
        return 1 if failures else 0
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
