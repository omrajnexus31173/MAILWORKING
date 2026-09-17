# Bulk ingestion & mailbox connectors (MailTrace AI ≥ 1.1)

> **Problem.** Analysing one email meant *download the .eml → upload it*. Fine for five emails, impossible for 1,000.
> **Solution.** An `.eml` is nothing but the raw RFC 5322 bytes that every mail system already holds. MailTrace now
> pulls those bytes itself, from three kinds of *mail source*, and pushes every message through the same
> analysis pipeline — deduplicated, sealed as evidence and custody-logged automatically.

## 1. The three ways in

| Tier | Source | How | Credentials | Best for |
|---|---|---|---|---|
| 1 | **Bulk file import** | drop an `.mbox` (Google Takeout / Thunderbird / Apple Mail), a `.zip` of `.eml`/`.msg`, a folder, or hundreds of `.eml` at once | none | forensic investigation of an exported mailbox; offline demos |
| 2 | **IMAP connector** | read-only IMAP: `EXAMINE` + `UID SEARCH SINCE` + `UID FETCH … BODY.PEEK[]` — byte-identical to an `.eml`; back-fill by date, then incremental by UID; `monitor` (poll) or `idle` (server push, RFC 2177) | app password or OAuth2 (XOAUTH2) | the universal automation: Gmail, Zoho, Yahoo, institutional Dovecot/Zimbra/Exchange, lab servers |
| 3 | **Report / journal mailbox** | users *Forward as attachment* to `phish-report@org`, or the admin journals/BCCs all mail to `mail-journal@org`; MailTrace watches that one mailbox and **unwraps the attached original** (headers intact) | one service mailbox | organisation-wide rollout, zero user effort, no access to personal inboxes |

Manual `.eml` upload and paste still work — they are just one more source.

## 2. Pipeline

```
 source ──▶ (unwrap message/rfc822 wrapper) ──▶ SHA-256 ──▶ already in evidence store? ──▶ duplicate, custody note
                                                                  │ no
                                                                  ▼
                       write-once evidence/<sha>.eml  +  custody "ingested from imap://host/INBOX;uid=4711 by X"
                                                                  │
   PHASE 1 · TRIAGE  (worker pool, no network)  ◀─────────────────┘
       header forensics on recorded Authentication-Results · NLP · URL / attachment analysis · cached GeoIP
       → provisional score saved as a case, SSE event, campaign re-cluster every 25 msgs      (~20-60 ms / email)
                                                                  │
   PHASE 2 · ENRICH  (worst provisional score first, cached + rate-limited resolvers)
       live SPF / DKIM / DMARC · GeoIP batch (≤100 IPs per call, 45 req/min budget) · RDAP · PTR · Tor
       → final score, custody "enrich", alerts for anything that crossed 60                    (skipped in offline mode)
```

Why two phases: 1,000 emails contain far fewer than 1,000 unique IPs/domains, and live lookups cost 1-9 s per *new*
indicator. Triaging everything first means the dashboard is fully populated within seconds and the most dangerous
emails get their full attribution first, instead of the analyst waiting for newsletter #612 to be geolocated.

Measured on the reference laptop-class sandbox (4 workers): **1,000-email mbox → triage complete in 12 s, fully
enriched in 27 s (≈2,200 emails/min end-to-end with warm caches); 305 emails cold: 22 s.**

Engineering that keeps it honest at scale: bounded in-flight queue (a 2 GB Takeout streams, never loads into RAM);
per-message error isolation (one malformed mail never aborts the other 999); SQLite WAL mode; campaign clustering only
over suspicious-or-worse cases with benign-infrastructure filtering (an ESP relay IP shared by 700 newsletters is not a
campaign); coalesced GeoIP batching; RDAP 429 back-off with transient (2-minute) instead of 3-day negative caching;
per-folder `last_uid` checkpoint so a closed laptop resumes exactly where it stopped.

## 3. Using it

**Mail Sources** (left nav) →

* **Bulk file import** — drop the file(s). Options: *unwrap wrappers* (on by default), *deep-enrich only if provisional
  score ≥ N* (set 35 for 10k+ mailboxes to skip enrichment of obviously clean mail).
* **Connect mailbox** — pick a provider preset (Gmail, Outlook/M365, Zoho, Yahoo, NIC, custom), enter host / port /
  user / app password, folders (e.g. `INBOX, [Gmail]/Spam`), *since* date, mode:
  * `manual` — fetch when you click **▶ Fetch all** (back-fill) or **↻ New only** (incremental);
  * `monitor` — poll every N minutes (incremental);
  * `IDLE` — one persistent connection, the server pushes; new mail is scored ~0.3 s after arrival (verified).
  **Test connection** lists folders, counts messages since the date and reports IDLE support without storing anything.
* **Ingestion jobs** — live progress cards (triage bar with malicious share in red, enrichment bar, rate, ETA), **Stop**,
  and **Cases** → case list filtered to that job. The nav badge shows running totals from any page.

Cases carry `source` (`imap` / `import` / `upload` / `sample`) and `source_ref`
(`imap://host/INBOX;uidvalidity=…;uid=…` or `file://takeout.mbox#msg812 | unwrapped message/rfc822 attachment
(reported by ravi@…)`), visible in the case header and in every custody entry.

### Provider notes

| Provider | Host | Auth | Notes |
|---|---|---|---|
| Gmail / Workspace | `imap.gmail.com:993` | **App Password** (2-Step Verification → App passwords) | enable IMAP in Gmail settings; folders `INBOX`, `[Gmail]/Spam`; a personal account is fine for demos |
| Outlook.com / Microsoft 365 | `outlook.office365.com:993` | **OAuth2** only (basic auth removed) | paste an access token with scope `https://outlook.office.com/IMAP.AccessAsUser.All` (MSAL device-code flow / tenant app registration); tokens expire in ~1 h — a refresh-token flow is the production follow-up |
| Zoho | `imap.zoho.in:993` | app-specific password | enable IMAP access in Zoho settings |
| Yahoo | `imap.mail.yahoo.com:993` | app password | |
| NIC / gov.in | `mail.gov.in:993` | password | subject to Kavach 2FA and departmental policy — needs IT approval |
| Lab (pymap / Dovecot / GreenMail) | `127.0.0.1:1143` | `plain-insecure` | for offline demos: `pip install pymap && pymap --host 127.0.0.1 --port 1143 dict --demo-data`, then `python scripts/make_test_mailbox.py --n 300 --imap 127.0.0.1:1143 demouser demopass` |

`scripts/make_test_mailbox.py --n 1000 --out demo.mbox` builds a realistic mailbox (72 % benign traffic, mutated attack
variants, forward-as-attachment reports, journal wrappers, exact duplicates) for demos and load tests.

## 4. Security & privacy design

* **Read-only by construction** — `EXAMINE` + `BODY.PEEK[]`: nothing is marked read, moved or deleted. No response
  actions (quarantine) are implemented on purpose; those need write scope and an explicit analyst decision.
* **Transport** — IMAPS (993) with certificate verification, or STARTTLS on 143; `plain-insecure` exists only for
  loopback lab servers and is labelled as such.
* **Secrets** — never returned by the API; stored obfuscated with a per-installation key file (`.mailtrace.key`, 0600)
  in the data folder. Production follow-up: Windows DPAPI / OS keyring.
* **Data minimisation** — bodies never leave the machine; only IPs/domains go to GeoIP/RDAP, and *Offline mode*
  stops even that. Retention/masking settings apply to imported cases like any other.
* **Authorisation & custody** — each source records *who authorised monitoring*; it is written into the chain of
  custody of every case fetched from it. Only connect mailboxes you own or are explicitly authorised to monitor
  (IT Act 2000 §43/§66; DPDP Act 2023).
* **Attachments** are hashed and parsed, never executed.

## 5. API

| Method & path | Purpose |
|---|---|
| `GET/POST /api/sources`, `PUT/DELETE /api/sources/{id}` | manage mail sources (`secret` write-only) |
| `POST /api/sources/test[?sid=]` | connect, list folders, count messages, detect IDLE |
| `POST /api/sources/{id}/run` `{mode: backfill\|incremental, limit, deep_min_score}` | start a fetch job |
| `POST /api/import/upload` (multipart `files`, `unwrap`, `deep_min_score`) | bulk import `.mbox` / `.zip` / `.eml` |
| `POST /api/import/path` `{paths}` | desktop only: import local paths without copying |
| `GET /api/jobs`, `GET /api/jobs/{id}` (with items), `POST /api/jobs/{id}/cancel` | job monitoring |
| `GET /api/cases?job=&source=&min_score=` | case list filters |
| SSE `/api/events` — `job`, `job-done`, `enriched` events in addition to `case` / `alert` | live progress |

## 6. Limitations & next steps

1. **Microsoft 365 needs OAuth2** with tenant consent; the connector speaks XOAUTH2 but obtaining/refreshing the token
   is left to the operator (MSAL device-code flow is the ~40-line follow-up). Gmail OAuth (instead of app passwords)
   likewise; app passwords are the pragmatic student-project path.
2. **Header integrity** — only forward-as-attachment, IMAP/API fetch or journaling preserve original headers. Inline
   forwards are analysed as what they are (a mail from the forwarder) and show the forwarder's infrastructure.
3. **Throughput is network-bound** in phase 2 and third-party services rate-limit (ip-api 45 req/min, rdap.org 429s).
   Caching, batching and worst-first ordering make it acceptable; a local GeoLite2 database would remove the limit.
4. **Desktop lifecycle** — IDLE/monitor stop when the window closes; for 24×7 monitoring run the backend in server mode
   (`run.bat` / `uvicorn main:app`) on a small VM and use the desktop app or browser as the console.
5. **`.msg` files** are converted best-effort (transport headers + text); install `extract-msg` for full fidelity.
6. **Encrypted bodies** (S/MIME, PGP) can't be inspected — headers still are.
7. **Language** — the NLP model is English-trained; header/URL signals still work on Hindi/Hinglish lures.

## Per-mailbox view (v1.2)

Every case records the **mailbox** it belongs to: the IMAP login (mail ID) for connector fetches, the export file name for bulk
imports, `demo corpus` for the bundled samples and `manual upload` for single-file analyses. The **Mailboxes** page lists one
card per mail ID with totals, malicious/suspicious counts and campaigns; choosing a mailbox there (or in the selector bar at the
top of Dashboard, Cases, Campaigns and Link Analysis) scopes those views to that mailbox only. The selection is remembered until
you click **show all**. Campaigns remain cross-mailbox by design — when scoped, a campaign is shown if it hit the selected
mailbox, with that mailbox's emails first and other victims greyed out, so the analyst still sees the whole operation.

API: `GET /api/mailboxes`; `mailbox=<id>` query parameter on `/api/cases`, `/api/stats`, `/api/campaigns`, `/api/graph`.
