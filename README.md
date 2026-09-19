# MailTrace AI — final production build

Email-threat forensics console: real IMAP/Gmail monitoring, a real analysis pipeline,
an honest geolocation layer, a 3D threat globe, an animated 3D snake background and a
notification centre — packaged as a runnable Windows desktop app.

```
README.md                        this file
RUN.txt                          START HERE — how to run, how monitoring works, limitations
MAILWORKING/MailTrace AI/        the packaged app
    MailTrace AI.exe             compiled launcher (reads _internal at runtime)
    Unblock-Windows.bat          fix "window never opens" (Mark of the Web)
    Start-MailTrace-AI.bat       unblock + launch
    Start-Engine-and-Open.bat    run the engine and open the console in a browser
    _internal/frontend/          UI (HTML/CSS/JS, vendored three.js — fully offline)
    _internal/backend/           FastAPI engine, analyzer, models, config, samples
MAILWORKING/docs/                solution document + ingestion guide
MAILWORKING/demo/                300-message demo mailbox (.mbox)
tools/                           test harnesses (tools/README.md), build_release.sh
```

**Quick start (Windows):** unzip → if the window does not open, run `Unblock-Windows.bat`
(then `Start-MailTrace-AI.bat`) → `MAILWORKING\MailTrace AI\MailTrace AI.exe`.

**Quick start (any OS / server):**
```bash
pip install fastapi "uvicorn[standard]" networkx dnspython requests python-multipart tldextract reportlab
cd "MAILWORKING/MailTrace AI/_internal/backend"
python -m uvicorn main:app --host 0.0.0.0 --port 8000
# open http://localhost:8000
```

Rebuild the release archive with `bash tools/build_release.sh`.
