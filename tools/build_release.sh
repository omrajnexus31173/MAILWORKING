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
  | tar -x -C "$STAGE"

# the launcher helpers next to the .exe too, so they are found from either folder
cp Unblock-Windows.ps1 Unblock-Windows.bat Start-MailTrace-AI.bat Start-Engine-and-Open.bat "$APP/"

rm -f "$OUT"
( cd "$STAGE" && zip -rq "$OUT" . -x '*.git*' '*__pycache__*' '*.pyc' '*.zip' )

echo "built: $OUT"
unzip -tq "$OUT" && echo "integrity: OK"
unzip -l "$OUT" | tail -2
