"""Forensic PDF report generator (ReportLab). Structured for institutional action / LEA hand-off."""
import io, json, time, hashlib
from typing import Dict, Any, List
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from xml.sax.saxutils import escape

SEV_COLOR = {"critical": colors.HexColor("#b91c1c"), "high": colors.HexColor("#c2410c"), "medium": colors.HexColor("#a16207"), "low": colors.HexColor("#1d4ed8"), "info": colors.HexColor("#4b5563")}

def _p(txt, style):
    return Paragraph(escape(str(txt if txt is not None else "—")).replace("\n", "<br/>"), style)

def _lbl(txt, style):
    return Paragraph(f"<b>{escape(str(txt))}</b>", style)

def _mask(addr: str, on: bool) -> str:
    if not on or not addr or "@" not in addr: return addr or "—"
    u, d = addr.split("@", 1)
    return (u[:2] + "***" if len(u) > 2 else "***") + "@" + d

def build_pdf(case: Dict[str, Any], org: Dict[str, Any], analyst: str = "MailTrace Analyst") -> bytes:
    r = case["result"]; h = r["headers"]; a = r["attribution"]; s = r["score"]; g = a.get("origin_geo") or {}
    mask = bool(org.get("masking", {}).get("mask_recipient_pii", False))
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"MailTrace Forensic Report {case['id']}", author="MailTrace AI")
    ss = getSampleStyleSheet()
    H1 = ParagraphStyle("h1", parent=ss["Title"], fontSize=17, spaceAfter=4, textColor=colors.HexColor("#0f172a"))
    H2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12.5, spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#1e293b"))
    B = ParagraphStyle("b", parent=ss["BodyText"], fontSize=8.8, leading=11.5)
    SM = ParagraphStyle("sm", parent=B, fontSize=7.6, leading=9.5, textColor=colors.HexColor("#334155"))
    MONO = ParagraphStyle("mono", parent=B, fontName="Courier", fontSize=7.2, leading=8.8)
    story: List[Any] = []

    verdict_col = {"malicious": "#b91c1c", "likely_malicious": "#c2410c", "suspicious": "#a16207", "low_risk": "#15803d", "clean": "#15803d"}[s["verdict"]]
    story += [_p("MailTrace AI — Email Threat & Origin Forensic Report", H1),
              _p(f"Case {case['id']} · Generated {time.strftime('%d %b %Y %H:%M UTC', time.gmtime())} · Organisation: {org.get('organization', '—')} · Prepared by: {analyst}", SM),
              Spacer(1, 6)]
    top = [[_lbl("Verdict", B), Paragraph(f'<font color="{verdict_col}"><b>{escape(s["label"])}</b></font> — risk score <b>{s["score"]}/100</b>', B)],
           [_lbl("Threat type", B), _p(r["threat"]["primary"].replace("_", " ").title() + (" (+ " + ", ".join(x.replace("_", " ") for x in r["threat"]["secondary"]) + ")" if r["threat"]["secondary"] else ""), B)],
           [_lbl("Subject", B), _p(h["subject"], B)],
           [_lbl("From", B), _p(f'{h["from"]["name"]} <{h["from"]["address"]}>' if h["from"]["name"] else h["from"]["address"], B)],
           [_lbl("Reply-To", B), _p(h["reply_to"]["address"] or "—", B)],
           [_lbl("Recipient", B), _p(_mask(h["to"], mask), B)],
           [_lbl("Date header", B), _p(h["date"], B)],
           [_lbl("Message-ID", B), _p(h["message_id"] or "(missing)", MONO)],
           [_lbl("Evidence SHA-256", B), _p(r["sha256"], MONO)],
           [_lbl("Most likely scenario", B), _p(f'{a["scenario_label"]} (confidence {int(a["confidence"]*100)}%)', B)],
           [_lbl("Probable origin", B), _p(f'{a.get("origin_ip") or "—"} · {", ".join(x for x in [g.get("city"), g.get("regionName"), g.get("country")] if x) or "unknown"} · {g.get("isp") or ""} · {g.get("category") or ""} · location confidence {int(a["location_confidence"]*100)}%', B)]]
    t = Table(top, colWidths=[36 * mm, 142 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]))
    story += [t, Spacer(1, 6), _p("1. Executive summary", H2), _p(r["summary"], B)]

    story += [_p("2. Authentication & identity analysis", H2)]
    au = h["auth"]
    auth_rows = [["Check", "Result", "Detail"],
                 ["SPF", au["spf"], f'evaluated on {au["spf_domain"]} — aligned: {"yes" if au["spf_aligned"] else "no"}. {au["live"].get("spf_detail") or ""}'],
                 ["DKIM", au["dkim"], (", ".join("d=" + d for d in au["dkim_domains"]) or "no signature") + f' — aligned: {"yes" if au["dkim_aligned"] else "no"}; crypto-verified: {au["dkim_crypto_verified"]}'],
                 ["DMARC", au["dmarc"], f'policy p={au["dmarc_policy"] or "none/absent"}; record: {au["live"].get("dmarc_record") or "—"}'],
                 ["Return-Path", h["return_path"]["address"] or "—", "envelope sender (bounce address)"],
                 ["MX of sender domain", ", ".join(au["live"].get("mx") or []) or "—", ""],
                 ["Receiver Auth-Results", "header", "; ".join(au["receiver_auth_results"])[:400] or "— (none; verdicts above are MailTrace live evaluations)"]]
    t = Table([[_p(c, SM) for c in row] for row in auth_rows], colWidths=[30 * mm, 28 * mm, 120 * mm], repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [t]

    story += [_p("3. Transmission path (origin → recipient)", H2),
              _p("Hops are ordered from the earliest sending node to the final delivery. 'trusted' hops were stamped by the recipient's or a known provider's infrastructure; 'unverifiable' hops appear below the earliest reliable node and may be forged by the sender.", SM)]
    rows = [["#", "IP / Host", "Location", "ISP / ASN", "Class", "Trust", "Timestamp", "Δs"]]
    for p in r["trace_path"]:
        rows.append([str(p["position"]), f'{p["ip"]}\n{(p.get("rdns") or p.get("host") or "")[:40]}', ", ".join(x for x in [p.get("city"), p.get("countryCode")] if x) or ("internal" if p["private"] else "?"),
                     (p.get("isp") or "")[:34], ", ".join(p.get("tags") or [])[:40], p.get("trust") or "", (p.get("timestamp") or "")[:19].replace("T", " "), str(p.get("delay_s")) if p.get("delay_s") is not None else ""])
    t = Table([[_p(c, SM) for c in row] for row in rows], colWidths=[7 * mm, 46 * mm, 26 * mm, 32 * mm, 26 * mm, 16 * mm, 22 * mm, 8 * mm], repeatRows=1)
    style = [("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("VALIGN", (0, 0), (-1, -1), "TOP")]
    for i, p in enumerate(r["trace_path"], 1):
        if p.get("trust") == "origin": style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fee2e2")))
    t.setStyle(TableStyle(style)); story += [t]
    o = h["origin"]
    story += [Spacer(1, 3), _p(f'<b>Earliest reliable origin:</b> {o.get("origin_ip") or "not determinable"} — method: {o.get("origin_kind","").replace("_"," ")} (hop confidence {int(o.get("confidence",0)*100)}%). ' + " ".join(o.get("notes", [])), B)]

    story += [_p("4. Origin geolocation, infrastructure & registry intelligence", H2)]
    reg = r.get("origin_ip_registry") or {}
    di = r.get("domain_intel") or {}
    geo_rows = [["Attribute", "Value"],
                ["Origin IP", a.get("origin_ip") or "—"],
                ["GeoIP (ip-api)", ", ".join(x for x in [g.get("city"), g.get("regionName"), g.get("country")] if x) or "—" + f'  (lat {g.get("lat")}, lon {g.get("lon")})' if g.get("lat") else ", ".join(x for x in [g.get("city"), g.get("regionName"), g.get("country")] if x) or "—"],
                ["ISP / Org / ASN", " · ".join(x for x in [g.get("isp"), g.get("org"), g.get("as")] if x) or "—"],
                ["Reverse DNS", g.get("reverse") or "none"],
                ["Infrastructure class", f'{g.get("category") or "—"}  tags: {", ".join(g.get("tags") or [])}'],
                ["RIR netblock", f'{reg.get("netname") or "—"} · {reg.get("rir") or ""} · registered country {reg.get("country") or "—"} · org {reg.get("org") or "—"}'],
                ["Abuse contact (for takedown / legal request)", ", ".join(reg.get("abuse_contacts") or []) or "—"],
                ["Sender domain registration", (f'{di.get("domain")} — created {str(di.get("created",""))[:10]} ({di.get("age_days")} days old), registrar {di.get("registrar") or "?"}, NS {", ".join(di.get("nameservers") or [])[:80]}' if di.get("found") else f'{di.get("domain") or "—"}: {di.get("note") or ("free webmail provider" if di.get("freemail") else "no registration data")}; resolves: {di.get("resolves")}')],
                ["Attribution reasoning", "\n".join("• " + x for x in a.get("reasons", []))]]
    t = Table([[_p(c, SM) for c in row] for row in geo_rows], colWidths=[42 * mm, 136 * mm], repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [t]

    story += [_p("5. Evidence / findings", H2)]
    rows = [["Severity", "Code", "Finding", "Detail"]]
    for f in r["findings"]:
        rows.append([f["severity"].upper(), f["code"], f["title"], f["detail"]])
    t = Table([[_p(c, SM) for c in row] for row in rows], colWidths=[17 * mm, 26 * mm, 52 * mm, 83 * mm], repeatRows=1)
    style = [("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("VALIGN", (0, 0), (-1, -1), "TOP")]
    for i, f in enumerate(r["findings"], 1):
        style.append(("TEXTCOLOR", (0, i), (0, i), SEV_COLOR.get(f["severity"], colors.black)))
    t.setStyle(TableStyle(style)); story += [t]

    nlp = r["content"]["nlp"]
    story += [_p("6. Content & NLP analysis", H2),
              _p(f'ML classifier phishing probability: <b>{(nlp.get("phishing_probability") or 0)*100:.1f}%</b> ({nlp.get("model","")}). Top phishing-indicative terms: {", ".join(t["term"] for t in nlp.get("top_terms", [])[:10]) or "—"}. Social-engineering cue score: {r["content"]["features"]["cue_score"]}/100. BEC patterns: {", ".join(r["content"]["features"]["bec_patterns"].keys()) or "none"}.', B)]
    if r["content"]["urls"]["urls"]:
        rows = [["Risk", "URL", "Flags"]] + [[str(u["risk"]), u["url"][:110], "; ".join(u["flags"])[:160]] for u in r["content"]["urls"]["urls"][:12]]
        t = Table([[_p(c, SM) for c in row] for row in rows], colWidths=[12 * mm, 86 * mm, 80 * mm], repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story += [Spacer(1, 3), _lbl("Links", B), t]
    if r["content"]["attachments"]["attachments"]:
        rows = [["Risk", "Filename", "Type / size", "SHA-256", "Flags"]] + [[str(x["risk"]), x["filename"], f'{x["content_type"]} / {x["size"]} B', x["sha256"], "; ".join(x["flags"])] for x in r["content"]["attachments"]["attachments"]]
        t = Table([[_p(c, SM) for c in row] for row in rows], colWidths=[12 * mm, 38 * mm, 30 * mm, 50 * mm, 48 * mm], repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story += [Spacer(1, 3), _lbl("Attachments", B), t]
    preview = (r["content"]["body"].get("text_preview") or "")[:1800]
    if preview and not org.get("masking", {}).get("mask_body_in_reports"):
        story += [Spacer(1, 3), _lbl("Body excerpt (as received)", B), _p(preview, MONO)]

    story += [_p("7. Indicators of Compromise (IOCs)", H2)]
    ioc = r["iocs"]
    ioc_rows = [["Type", "Value(s)"], ["Sender", ioc.get("sender")], ["Reply-To", ioc.get("reply_to")], ["Return-Path", ioc.get("return_path")], ["Origin IP", ioc.get("origin_ip")],
                ["All relay IPs", ", ".join(ioc.get("ips", []))], ["Domains", ", ".join(ioc.get("domains", []))], ["URLs", "\n".join(ioc.get("urls", [])[:12])],
                ["Attachment hashes", "\n".join(f'{x["name"]}: {x["sha256"]}' for x in ioc.get("attachment_hashes", []))], ["Crypto wallets / UPI / phones", ", ".join(ioc.get("crypto_wallets", []) + ioc.get("upi_ids", []) + ioc.get("phones", []))], ["Message-ID", ioc.get("message_id")]]
    t = Table([[_p(c, SM) for c in row] for row in ioc_rows if row[1]], colWidths=[36 * mm, 142 * mm], repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [t]

    story += [_p("8. Recommended actions", H2)]
    recs = recommendations(r, org)
    for x in recs: story.append(_p("• " + x, B))

    if case.get("related"):
        story += [_p("9. Related cases / campaign linkage", H2)]
        rows = [["Case", "Subject", "Sender", "Score", "Shared indicators"]] + [[x["case_id"], (x["subject"] or "")[:50], x["sender"], str(x["score"]), ", ".join(x["shared"])[:120]] for x in case["related"][:15]]
        t = Table([[_p(c, SM) for c in row] for row in rows], colWidths=[24 * mm, 50 * mm, 40 * mm, 12 * mm, 52 * mm], repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story += [t]

    story += [_p("10. Chain of custody", H2)]
    rows = [["Timestamp (UTC)", "Actor", "Action", "Detail", "Hash"]] + [[c["ts"], c["actor"], c["action"], c["detail"][:70], (c["hash_after"] or c["hash_before"] or "")[:20] + ("…" if c.get("hash_after") else "")] for c in case.get("custody", [])]
    t = Table([[_p(c, SM) for c in row] for row in rows], colWidths=[30 * mm, 24 * mm, 20 * mm, 66 * mm, 38 * mm], repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [t, Spacer(1, 6),
              _p("Evidentiary note: the original message was preserved verbatim as a read-only .eml artefact and sealed with SHA-256 at ingestion; every subsequent access or annotation is logged above. Geolocation is an estimate derived from IP-to-location databases and RIR registration data (typical accuracy: country ~99%, city ~50–80%); it identifies the network endpoint, not necessarily the person. VPN/Tor/cloud origins indicate infrastructure used, not the operator's location. Definitive attribution requires subscriber/log records obtainable from the identified providers through lawful process (e.g. Section 91 CrPC / BNSS 94 notice, IT Act 2000 s.69/79(3)(b) as applicable). This report is generated by an automated analysis system and should be reviewed by a qualified analyst before use in proceedings.", SM)]

    def footer(canvas, doc_):
        canvas.saveState(); canvas.setFont("Helvetica", 7); canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(16 * mm, 9 * mm, f"MailTrace AI · Case {case['id']} · SHA-256 {r['sha256'][:32]}… · CONFIDENTIAL — for authorised investigative use")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {doc_.page}"); canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()

def recommendations(r: Dict[str, Any], org: Dict[str, Any]) -> List[str]:
    a = r["attribution"]; s = r["score"]; h = r["headers"]; g = a.get("origin_geo") or {}; reg = r.get("origin_ip_registry") or {}
    out = []
    if s["verdict"] in ("malicious", "likely_malicious"):
        out.append("Quarantine the message organisation-wide (search by Message-ID / subject / sender) and purge from all mailboxes before user interaction.")
        out.append("Block the sender address, sender domain and all listed URL domains at the mail gateway, web proxy and DNS resolver.")
    if r["threat"]["primary"] in ("credential_phishing", "spoofing") or "credential_phishing" in r["threat"]["secondary"]:
        out.append("Identify recipients who clicked/submitted (proxy logs, IdP sign-in logs); force password reset + revoke sessions/tokens; enforce MFA.")
    if r["threat"]["primary"] == "business_email_compromise" or "business_email_compromise" in r["threat"]["secondary"]:
        out.append("Notify Finance/Accounts: verify any pending payment or beneficiary change through an out-of-band call to a known number. If money moved, report within the golden hour to 1930 / cybercrime.gov.in and the beneficiary bank for a lien/freeze.")
    if "malware_delivery" in [r["threat"]["primary"]] + r["threat"]["secondary"]:
        out.append("Submit attachment hashes to sandbox / AV; hunt endpoints for the hashes; isolate any host that opened the file.")
    if a["scenario"] == "compromised_account":
        out.append(f"Treat {h['from']['address']} as compromised: notify the domain owner's IT team, request rotation of credentials and review of mailbox rules/forwarding; request authentication logs for the submission IP {a.get('origin_ip')}.")
    if a["scenario"] == "attacker_owned_lookalike_domain":
        out.append(f"File registrar abuse / UDRP takedown for {h['from']['registered_domain']} (registrar: {(r.get('domain_intel') or {}).get('registrar') or 'see WHOIS'}); request registrant data via lawful request. Preserve DNS/WHOIS snapshots.")
    if a["scenario"] == "freemail_account":
        out.append(f"Send a preservation + subscriber-information request to the webmail provider ({h['from']['registered_domain']}) for account {h['from']['address']}: registration IP, recovery phone/email, login IP history with timestamps.")
    if reg.get("abuse_contacts"):
        out.append(f"Send abuse report + log-preservation request to the network owner of {a.get('origin_ip')}: {', '.join(reg['abuse_contacts'])} ({reg.get('netname')}, {reg.get('rir')}).")
    if g.get("tags") and ("TOR_EXIT" in g["tags"] or "PROXY/VPN" in g["tags"] or "VPN_PROVIDER" in g["tags"]):
        out.append("Origin is anonymised (Tor/VPN): do not rely on the geolocation for attribution; pivot on the reply-to address, payment rails (UPI/bank/crypto wallet), phone numbers and the landing-page hosting instead.")
    if r["iocs"].get("upi_ids") or r["iocs"].get("phones"):
        out.append("Payment rails (UPI IDs / phone numbers) are strong identity pivots: request KYC details from the PSP/bank and telecom CAF from the operator via the nodal officer.")
    out.append("Raise awareness: circulate a sanitised screenshot to the targeted user group; add this lure to the phishing-simulation library.")
    if s["verdict"] in ("clean", "low_risk"):
        out = ["No action required. Message authenticated and content appears benign; retain analysis for baseline modelling."]
    return out
