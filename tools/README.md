# MailTrace AI — test harnesses

Both suites run against a **live** MailTrace AI backend (`http://127.0.0.1:8000`) and use only
real API data — nothing is mocked except browser APIs jsdom does not implement.

## Backend / API regression (no extra dependencies)

```bash
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000   # from MailTrace AI/_internal/backend
python3 tools/test_api.py
```

Checks: health + engine version, stats/cases/campaigns/graph/geo-hotspots/lookup, the **streaming**
`/api/analyze/stream` NDJSON pipeline (real stage events), score/verdict/geolocation/trace-path,
and PDF + JSON report generation with the chain of custody.

## Frontend / motion layer (jsdom)

```bash
npm i jsdom@24            # only for this test; the app itself has no build step or dependencies
node tools/test_motion.js            # full motion path
REDUCE=1 node tools/test_motion.js   # with prefers-reduced-motion: reduce
```

Checks: every static asset is served, the boot splash dismisses on the real health response,
dashboard entrance (reveal blocks, staged children, animated counters, decoded headline, globe),
micro-interactions (press ripple, cursor spotlight), route-transition veil, the AI-processing
canvas mounting **only while the backend is working** and being removed when it finishes,
staged threat-result reveal, the animated forensic timeline, all nine routes rendering, and a
clean console in both normal and reduced-motion mode.

> jsdom has no WebGL, so the globe is asserted to mount either as a WebGL canvas **or** as the
> documented flat-map fallback. Real-browser visuals (animation smoothness, layout, 60 fps) must
> still be checked by eye in a browser.
