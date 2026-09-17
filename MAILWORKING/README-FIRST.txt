MailTrace AI 1.2.0  —  AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence
SIH 2026 · Problem Statement 26106 · AICTE Cyber Security Cell
=====================================================================================

WHAT IS IN THIS ZIP
  MailTrace AI\MailTrace AI.exe   the desktop application (portable — no installation needed)
  demo\demo_mailbox_300.mbox      a 300-email mailbox export for the bulk-import demo
  docs\INGESTION.md               Mail Sources / IMAP operator guide
  docs\MailTrace-AI_Solution.docx the written solution document

REQUIREMENTS
  Windows 10/11 64-bit. Microsoft Edge WebView2 runtime (already present on Windows 10 21H2+ / Windows 11).
  If Windows SmartScreen shows "Windows protected your PC": click "More info" -> "Run anyway".
  IMPORTANT: extract the WHOLE zip first (right-click -> Extract All). Do not run the exe from inside the zip.

START
  1. Double-click  MailTrace AI\MailTrace AI.exe
  2. The dashboard opens with 11 built-in demo cases already analysed.

DEMO 1 — BULK IMPORT (30 seconds, no internet needed)
  1. Left nav -> Mail Sources
  2. Drag  demo\demo_mailbox_300.mbox  onto the import zone (or click "Import files")
  3. Watch the job card: 305 messages -> 300 analysed, 5 duplicates caught, ~84 malicious
  4. Open Campaigns: 6 attack campaigns clustered automatically. Open any case -> Trace / Report PDF.

DEMO 2 — CONNECT A REAL MAILBOX OVER IMAP (Gmail, 2 minutes)
  Gmail preparation (once):  Google Account -> Security -> 2-Step Verification: ON
                             -> App passwords -> create one (16 characters)
  1. Mail Sources -> Connect mailbox -> preset "Gmail"
     host imap.gmail.com, port 993, username = your address, password = the App Password
     folders: INBOX  (add "[Gmail]/Spam" to analyse spam too), since: any date
     mode:  manual  = fetch on button press
            monitor = poll every N minutes
            idle    = server push, new mail analysed within ~1 second
  2. Test  -> shows folders and message counts (nothing is stored)
  3. Fetch all -> every email is pulled, sealed as evidence, analysed and clustered.
     Later use "New only" — only messages newer than the last fetch are pulled.
  Other providers: Zoho (imap.zoho.in), Yahoo (imap.mail.yahoo.com, app password), Outlook.com / Microsoft 365
  (OAuth2 token — see docs\INGESTION.md), NIC / institutional servers (ask IT for IMAP host; usually port 993).

DEMO 3 — PHISHING-REPORT MAILBOX (organisation-wide)
  Connect the mailbox that users forward suspicious emails to ("Forward as attachment") and tick
  "unwrap wrappers". The ORIGINAL message inside the report is traced, not the forwarder.

DEMO 4 — ONE MAILBOX AT A TIME (new in 1.2)
  Left nav -> Mailboxes: one card per mail ID / import file with its own counts.
  Click a card (or its Cases / Campaigns / Dashboard buttons) -> those pages show ONLY that mailbox's emails.
  The blue "Mailbox" bar at the top of Dashboard / Cases / Campaigns / Link Analysis switches mailboxes;
  "show all" returns to the combined view. The choice is remembered until you change it.

SECURITY NOTES
  Read-only IMAP (BODY.PEEK): nothing on the server is marked read, moved or deleted.
  TLS on 993. Passwords are stored encrypted in the data folder and never shown again in the UI or API.
  Email bodies never leave your PC; only IPs/domains are looked up (switch Offline mode in Settings to stop even that).
  Only connect mailboxes you own or are explicitly authorised to monitor (IT Act 2000 s.43/66, DPDP Act 2023).

DATA FOLDER
  %LOCALAPPDATA%\MailTrace AI   (database, sealed evidence, encrypted source secrets, logs)
  Delete it to reset the application.

TROUBLESHOOTING
  App does not open / "Failed to resolve Python.Runtime": right-click the extracted folder -> Properties ->
  "Unblock" (files copied from another PC carry a download flag). The app also does this itself on first run.
  Log file: %LOCALAPPDATA%\MailTrace AI\mailtrace_desktop.log
