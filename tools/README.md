# MailTrace AI — test harnesses

Both suites run against a **live** MailTrace AI backend (`http://127.0.0.1:8000`) and use only
real API data — nothing is mocked except browser APIs jsdom does not implement.

## Backend / API regression (no extra dependencies)

```bash
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000   # from MailTrace AI/_internal/backend
python3 tools/test_api.py                                # 51 assertions
```

* service: health, engine version, NLP model load
* real data: stats, cases, campaigns, geo hotspots (**precision labels, no invented coordinates**),
  link-analysis graph, IP/domain lookup
* streaming pipeline: `/api/analyze/stream` NDJSON stage events, score/verdict/geolocation/trace-path
* reports: PDF + JSON + chain of custody
* **notifications**: history stored, unread counter, every threat notification maps to a real
  high-risk case, mark-all-read
* **background monitoring**: monitor running, account create/selection persistence (deselect →
  persisted, reselect → persisted), connection-failure handling (no crash, readable message),
  scan-now, failed scan records a real error + notification, checkpoint never fakes progress,
  pause/resume, account removal

## Frontend / motion layer (jsdom)

```bash
npm i jsdom@24            # only for this test; the app itself has no build step or dependencies
node tools/test_motion.js            # 84 assertions — full motion path
REDUCE=1 node tools/test_motion.js   # 74 assertions — with prefers-reduced-motion: reduce
```

* assets served, boot splash dismissed on the real health response, ambient orbs, motion tier
* dashboard entrance: reveal blocks, staged children, animated counters, decoded headline, globe
  (WebGL canvas **or** documented flat-map fallback), threat rows
* micro-interactions: press ripple, cursor spotlight tracking
* route-transition veil, AI-processing canvas mounted **only while the backend works** and removed
  when it finishes, 12-stage pipeline
* case detail: staged reveal, **threat-result hero** (MALICIOUS / SUSPICIOUS / CLEAN with real NLP
  confidence or "unavailable"), animated timeline, background-mode control
* **3D snake**: mounts, long body, render loop runs, head actually moves, body stays connected, disposes
* **mail accounts**: monitoring bar, account cards with status pill / last-checked / checkpoint,
  Gmail prefilled connect form, UI toggle persisted server-side, styled confirm modal
* **notification centre**: bell + badge, panel with real history, severity styling, toast rendering
* all ten routes render, console clean (normal *and* reduced-motion mode)

> jsdom has no GPU: the globe is asserted as canvas **or** fallback, and the snake is exercised with a
> stubbed `THREE.WebGLRenderer` so its motion maths still runs. Real-browser visuals (smoothness,
> layout, fps) must be checked by eye.
