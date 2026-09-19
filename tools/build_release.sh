#!/usr/bin/env bash
# Build MailTrace-AI-FINAL-PRODUCTION.zip from the committed tree.
# Uses `git archive` so only tracked files are packaged: no .git, no __pycache__,
# no runtime data (mailtrace.db, evidence/, uploads/, intel_cache.json, .mailtrace.key).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-$HOME/MailTrace-AI-FINAL-PRODUCTION.zip}"
STAGE="$(mktemp -d)/MailTrace-AI"
APP="$STAGE/MAILWORKING/MailTrace AI"

rm -rf "$STAGE"; mkdir -p "$STAGE"
cd "$ROOT"

git archive HEAD \
  "MAILWORKING/MailTrace AI" "MAILWORKING/docs" "MAILWORKING/demo" \
  tools RUN.txt README.md \
  Unblock-Windows.ps1 Unblock-Windows.bat Start-MailTrace-AI.bat Start-Engine-and-Open.bat \
  Check-Runtime.ps1 Check-Runtime.bat \
  | tar -x -C "$STAGE"

# the launcher helpers next to the .exe too, so they are found from either folder
cp Unblock-Windows.ps1 Unblock-Windows.bat Start-MailTrace-AI.bat Start-Engine-and-Open.bat \
   Check-Runtime.ps1 Check-Runtime.bat "$APP/"

# build manifest
{
  echo "MailTrace AI - FINAL PRODUCTION BUILD"
  echo "built      : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit     : $(git rev-parse HEAD)"
  echo "branch     : $(git rev-parse --abbrev-ref HEAD)"
  echo "files      : $(find "$STAGE" -type f | wc -l)"
  echo "engine     : $(grep -m1 'ENGINE_VERSION' "$APP/_internal/backend/main.py" 2>/dev/null || echo 1.3.0) (backend/main.py)"
  echo
  echo "sha256 (MailTrace AI.exe): $(sha256sum "$APP/MailTrace AI.exe" | cut -d' ' -f1)"
  echo
  echo "Verify after extracting:  python3 tools/verify_release.py <extracted-folder>"
  echo "Start here:               RUN.txt"
} > "$STAGE/BUILD-INFO.txt"

rm -f "$OUT"
# NOTE: never exclude '*.zip' here - _internal/base_library.zip is a zip file and is
# required by the PyInstaller bootloader ("Failed to start embedded python interpreter!"
# when it is missing). Only the two top-level archives are excluded, and they are not in
# the git-archive paths anyway.
( cd "$STAGE" && zip -rq "$OUT" . -x '*.git*' '*__pycache__*' '*.pyc' \
    'MAILWORKING.zip' 'MailTrace-AI-FINAL-PRODUCTION.zip' )

echo "built: $OUT"
unzip -tq "$OUT" && echo "integrity: OK"
unzip -l "$OUT" | tail -2

# ---------------------------------------------------------------------------------
# Completeness gate: the archive must contain EVERY file of the original, working
# Windows package (MAILWORKING.zip) - this is what caught the missing
# _internal/base_library.zip. Runtime data (db, key, evidence, uploads, cache) is
# regenerated on first run and is intentionally not shipped.
# ---------------------------------------------------------------------------------
if [ -f "$ROOT/MAILWORKING.zip" ]; then
  python3 - "$OUT" "$ROOT/MAILWORKING.zip" <<'PY'
import sys, zipfile
mine, ref = zipfile.ZipFile(sys.argv[1]), zipfile.ZipFile(sys.argv[2])
SKIP = ("mailtrace.db", ".mailtrace.key", "intel_cache.json", "__pycache__", "evidence/", "uploads/")
def subset(z, prefix):
    return {n[len(prefix):] for n in z.namelist()
            if n.startswith(prefix) and not n.endswith("/") and not any(s in n for s in SKIP)}
ref_files = subset(ref, "MailTrace AI/")
out_files = subset(mine, "MAILWORKING/MailTrace AI/")
missing = sorted(ref_files - out_files)
print("packaging gate: %d reference files, %d shipped" % (len(ref_files), len(out_files)))
if missing:
    print("FAIL - missing %d file(s) the Windows package needs:" % len(missing))
    for f in missing[:20]:
        print("   -", f)
    sys.exit(1)
print("packaging gate: OK - no file of the original package is missing")
PY
  [ $? -ne 0 ] && exit 1
fi
