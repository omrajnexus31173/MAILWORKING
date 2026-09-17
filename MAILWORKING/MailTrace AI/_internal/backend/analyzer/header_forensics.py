"""
Email header & protocol forensics:
  - RFC-5322 parsing (From / Reply-To / Return-Path / Message-ID / Date ...)
  - Received chain reconstruction (top = last hop nearest the recipient, bottom = origin)
  - SPF evaluation against live DNS for the *earliest reliable* IP
  - DKIM: signature presence, d= alignment, and live cryptographic verification when possible
  - DMARC policy lookup + alignment
  - Authentication-Results / ARC parsing (receiver's own verdict, if present)
  - Anomaly detection: display-name spoofing, Reply-To mismatch, Return-Path mismatch,
    time-travel between hops, missing/forged Message-ID, X-Mailer artefacts, bulk-mailer traces ...
"""
import re, email, email.utils, email.policy, ipaddress, time
from email.header import decode_header, make_header
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from .common import (registered_domain, is_private_ip, valid_ip, find_ips, esp_for_host, FREEMAIL,
                     brand_match, normalize_homoglyphs, levenshtein, domain_label)
from . import intel

def _dh(v) -> str:
    if v is None:
        return ""
    try:
        return str(make_header(decode_header(str(v))))
    except Exception:
        return str(v)

def parse_message(raw: bytes):
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogateescape")
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    return msg

# ---------------------------------------------------------------- Received --
RECV_FROM = re.compile(r"^\s*from\s+(\S+)(?:\s*\(([^)]*)\))?", re.I | re.S)
RECV_BY = re.compile(r"\bby\s+(\S+)", re.I)
RECV_WITH = re.compile(r"\bwith\s+([A-Za-z0-9\-]+)", re.I)
RECV_ID = re.compile(r"\bid\s+(\S+)", re.I)
RECV_FOR = re.compile(r"\bfor\s+<?([^\s>;]+)>?", re.I)

def parse_received(headers: List[str]) -> List[Dict[str, Any]]:
    """headers[0] is the topmost (most recent) Received line."""
    hops = []
    n = len(headers)
    for idx, raw in enumerate(headers):
        h = re.sub(r"\s+", " ", raw.strip())
        d: Dict[str, Any] = {"raw": h, "position": n - idx, "index_from_top": idx}  # position 1 = origin
        m = RECV_FROM.match(h)
        if m:
            d["from_host"] = m.group(1).strip("[]()")
            paren = m.group(2) or ""
            d["from_comment"] = paren
            ips = find_ips(paren) or find_ips(m.group(1))
            d["from_ip"] = ips[0] if ips else None
            # HELO vs rDNS
            rd = re.match(r"^\s*([\w.\-]+)\s*\[", paren)
            if rd and not valid_ip(rd.group(1)):
                d["from_rdns"] = rd.group(1)
            if paren.lower().startswith("unknown") or "unknown" in paren.lower().split("[")[0]:
                d["from_rdns"] = "unknown"
            if valid_ip(d.get("from_host", "")):
                d["helo_is_ip"] = True
        else:
            d["from_host"] = None
            d["from_ip"] = None
        m = RECV_BY.search(h);  d["by_host"] = m.group(1).strip("[]();") if m else None
        m = RECV_WITH.search(h); d["protocol"] = m.group(1).upper() if m else None
        m = RECV_ID.search(h);   d["id"] = m.group(1).strip(";") if m else None
        m = RECV_FOR.search(h);  d["for"] = m.group(1) if m else None
        ts = None
        if ";" in h:
            try:
                ts = email.utils.parsedate_to_datetime(h.rsplit(";", 1)[1].strip())
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                ts = None
        d["timestamp"] = ts.isoformat() if ts else None
        d["_ts"] = ts
        d["tls"] = bool(re.search(r"\b(ESMTPS|ESMTPSA|TLS|SSL|UTF8SMTPS)\b", h, re.I)) or bool(re.search(r"\bversion=TLS", h, re.I))
        d["authenticated_submission"] = bool(re.search(r"\b(ESMTPSA|ESMTPA|LMTPA|UTF8SMTPSA)\b", h, re.I)) or "(authenticated" in h.lower()
        d["from_esp"] = esp_for_host(d.get("from_host") or "") or esp_for_host(d.get("from_rdns") or "")
        d["by_esp"] = esp_for_host(d.get("by_host") or "")
        d["from_private"] = bool(d["from_ip"]) and is_private_ip(d["from_ip"])
        hops.append(d)
    return hops

def find_origin(hops: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Walk from the recipient (top) downward. Hops written by the recipient's own MTA
    or by well-known ESP infrastructure are trusted. The first public IP that is
    *not* ESP infrastructure is the earliest reliable sending node. Anything below
    that is attacker-controllable and gets a low-trust flag.
    """
    trusted_boundary = None
    candidate = None
    for h in hops:                      # top -> bottom
        ip = h.get("from_ip")
        if not ip or is_private_ip(ip):
            continue
        by_trusted = h.get("by_esp") is not None
        from_trusted = h.get("from_esp") is not None
        if from_trusted and by_trusted:
            trusted_boundary = h
            continue                    # internal ESP relay, keep walking
        if from_trusted and not by_trusted:
            # Gmail -> our org: hop is trusted but next hop below would be inside Google (internal)
            candidate = h
            continue
        # public, non-ESP IP -> this is the earliest reliable node
        candidate = h
        break
    # If mail was *submitted* to an ESP with authentication, the authenticated client IP (below) is best
    submission = None
    for h in hops:
        if h.get("authenticated_submission") and h.get("from_ip") and not is_private_ip(h["from_ip"]):
            submission = h
    result = {"origin_hop": None, "origin_ip": None, "origin_kind": "unknown", "confidence": 0.2, "notes": []}
    if submission and (candidate is None or submission["position"] <= candidate["position"]):
        result.update(origin_hop=submission, origin_ip=submission["from_ip"], origin_kind="authenticated_submission",
                      confidence=0.85, notes=["Authenticated SMTP submission (ESMTPSA) — IP belongs to the client that logged into the mailbox"])
    elif candidate:
        result.update(origin_hop=candidate, origin_ip=candidate["from_ip"], origin_kind="earliest_public_relay",
                      confidence=0.7 if candidate.get("by_esp") or candidate["index_from_top"] <= 2 else 0.55,
                      notes=["Earliest public, non-ESP relay in a chain stamped by trusted receivers"])
    else:
        # fallback: bottom-most public IP
        for h in reversed(hops):
            if h.get("from_ip") and not is_private_ip(h["from_ip"]):
                if h.get("from_esp"):
                    result.update(origin_hop=h, origin_ip=h["from_ip"], origin_kind="esp_boundary", confidence=0.3,
                                  notes=[f"Message entered the mail system inside {h['from_esp']} infrastructure (webmail / API submission). The provider withholds the client IP; it is recoverable only from the provider's login/audit logs via lawful request."])
                else:
                    result.update(origin_hop=h, origin_ip=h["from_ip"], origin_kind="bottom_public_hop", confidence=0.35,
                                  notes=["Bottom-most public IP (could be forged: below any trusted boundary)"])
                break
    # hops below origin are attacker controllable
    if result["origin_hop"]:
        pos = result["origin_hop"]["position"]
        for h in hops:
            h["trust"] = "trusted" if h["position"] > pos else ("origin" if h["position"] == pos else "unverifiable")
        below = [h for h in hops if h["position"] < pos]
        if below:
            result["notes"].append(f"{len(below)} hop(s) below the origin are unverifiable (could be forged by sender)")
    return result

# ---------------------------------------------------------- Auth headers ---
def parse_auth_results(msg) -> Dict[str, Any]:
    out = {"spf": None, "dkim": None, "dmarc": None, "arc": None, "raw": []}
    for h in msg.get_all("Authentication-Results", []) + msg.get_all("ARC-Authentication-Results", []):
        s = re.sub(r"\s+", " ", str(h))
        out["raw"].append(s)
        for k in ("spf", "dkim", "dmarc", "arc"):
            m = re.search(rf"\b{k}=(\w+)", s, re.I)
            if m and out[k] is None:
                out[k] = m.group(1).lower()
    rs = msg.get("Received-SPF")
    if rs and out["spf"] is None:
        m = re.match(r"\s*(\w+)", str(rs)); out["spf"] = m.group(1).lower() if m else None
    return out

def parse_dkim_sigs(msg) -> List[Dict[str, str]]:
    sigs = []
    for h in msg.get_all("DKIM-Signature", []):
        s = re.sub(r"\s+", "", str(h))
        tags = dict(kv.split("=", 1) for kv in s.split(";") if "=" in kv)
        sigs.append({"d": tags.get("d", "").lower(), "s": tags.get("s", ""), "a": tags.get("a", ""), "h": tags.get("h", "")[:200]})
    return sigs

def verify_dkim(raw: bytes, sigs: List[Dict[str, str]]) -> Optional[bool]:
    """True = cryptographically valid, False = signature present but invalid, None = cannot verify (no key / offline)."""
    if intel.OFFLINE:
        return None
    try:
        import dkim
        # is the public key even published?
        key_found = False
        for s in sigs:
            if s.get("s") and s.get("d") and intel._txt(f"{s['s']}._domainkey.{s['d']}"):
                key_found = True
                break
        if not key_found:
            return None
        return bool(dkim.verify(raw))
    except Exception:
        return None

# ------------------------------------------------------------ Main entry ---
def analyze_headers(raw: bytes, org_domains: List[str], do_dns: bool = True) -> Dict[str, Any]:
    msg = parse_message(raw)
    t0 = time.time()
    findings: List[Dict[str, Any]] = []
    def flag(sev, code, title, detail, weight):
        findings.append({"severity": sev, "code": code, "title": title, "detail": detail, "weight": weight})

    frm = _dh(msg.get("From", ""))
    from_name, from_addr = email.utils.parseaddr(frm)
    from_addr = (from_addr or "").lower()
    from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
    from_reg = registered_domain(from_domain)
    reply_to = _dh(msg.get("Reply-To", ""))
    rt_name, rt_addr = email.utils.parseaddr(reply_to)
    rt_addr = (rt_addr or "").lower()
    rt_domain = rt_addr.split("@")[-1] if "@" in rt_addr else ""
    return_path = _dh(msg.get("Return-Path", ""))
    _, rp_addr = email.utils.parseaddr(return_path); rp_addr = (rp_addr or "").lower()
    rp_domain = rp_addr.split("@")[-1] if "@" in rp_addr else ""
    to_hdr = _dh(msg.get("To", ""))
    subject = _dh(msg.get("Subject", ""))
    msgid = (msg.get("Message-ID") or "").strip()
    date_hdr = msg.get("Date")
    x_mailer = msg.get("X-Mailer") or msg.get("User-Agent") or ""
    x_orig_ip = None
    for k in ("X-Originating-IP", "X-Sender-IP", "X-Client-IP", "X-Source-IP", "X-Real-IP"):
        if msg.get(k):
            ips = find_ips(str(msg.get(k)))
            if ips: x_orig_ip = ips[0]; break

    received_raw = [str(h) for h in msg.get_all("Received", [])]
    hops = parse_received(received_raw)
    origin = find_origin(hops)
    origin_ip = origin["origin_ip"]

    # ----- Identity anomalies -----
    fragment = not received_raw and not msgid and not date_hdr
    if fragment:
        flag("info", "H-FRAGMENT", "Transport headers missing — content-only analysis",
             "No Received / Message-ID / Date headers: this looks like a pasted body or forwarded fragment rather than a full .eml. Origin tracing and SPF/DKIM/DMARC cannot be evaluated; use 'Show original' / 'Save as .eml' for the full analysis.", 0)
    if not msgid and not fragment:
        flag("medium", "H-NO-MSGID", "Missing Message-ID", "Legitimate MTAs always add a Message-ID; absence suggests a hand-crafted or scripted message.", 8)
    else:
        mid_dom = msgid.split("@")[-1].rstrip(">").lower() if "@" in msgid else ""
        if mid_dom and from_reg and registered_domain(mid_dom) != from_reg and esp_for_host(mid_dom) is None and not any(from_reg.endswith(d) for d in FREEMAIL):
            flag("low", "H-MSGID-DOM", "Message-ID domain differs from From domain",
                 f"Message-ID @{mid_dom} vs From @{from_domain}. Common with bulk/relay tools; weak signal on its own.", 3)
    if not date_hdr and not fragment:
        flag("low", "H-NO-DATE", "Missing Date header", "RFC 5322 requires a Date header.", 3)
    if not received_raw and not fragment:
        flag("medium", "H-NO-RECEIVED", "No Received headers", "Message never traversed an MTA (locally generated / pasted / stripped). Origin cannot be traced from the chain.", 6)

    # display-name spoofing
    if from_name:
        nm = from_name.lower()
        m = re.search(r"[\w.+-]+@[\w.-]+\.\w+", nm)
        if m:
            embedded = m.group(0)
            if embedded.split("@")[-1] != from_domain:
                flag("high", "H-DN-EMAIL", "Email address embedded in display name",
                     f'Display name shows "{embedded}" but real sender is {from_addr}. Classic mobile-client spoof.', 22)
        bm = brand_match(nm.replace(" ", ""))
        if bm and bm[1] != "legit":
            brand = bm[0]
            legit_domains = [d for _, (_, ds) in __import__("analyzer.common", fromlist=["BRANDS"]).BRANDS.items() for d in ds] if False else None
            from .common import BRANDS
            if from_reg not in BRANDS[brand][1]:
                flag("high", "H-DN-BRAND", "Display name impersonates a brand",
                     f'Display name "{from_name}" references {brand} but sender domain is {from_domain}.', 20)
        if from_reg in FREEMAIL and org_domains:
            # executive impersonation from freemail
            pass

    # freemail + org name
    if from_reg in FREEMAIL and from_name and any(w in from_name.lower() for w in ("director", "principal", "registrar", "vc ", "vice chancellor", "chairman", "ceo", "cfo", "hr ", "accounts", "dean", "admin", "support", "helpdesk", "it dept")):
        flag("high", "H-FREEMAIL-ROLE", "Authority role name on freemail account",
             f'"{from_name}" is sent from {from_reg} — institutions do not use free webmail for official roles.', 15)

    # Reply-To divergence
    if rt_addr and rt_addr != from_addr:
        if registered_domain(rt_domain) != from_reg:
            sev, w = ("high", 18) if registered_domain(rt_domain) in FREEMAIL or from_reg not in FREEMAIL else ("medium", 10)
            flag(sev, "H-REPLYTO", "Reply-To points to a different domain",
                 f"Replies go to {rt_addr}, not {from_addr}. Used to hijack the conversation after a spoofed first mail.", w)
        else:
            flag("low", "H-REPLYTO-SAME", "Reply-To differs from From (same domain)", f"{rt_addr} vs {from_addr}", 1)

    # Return-Path divergence
    if rp_addr and rp_domain and registered_domain(rp_domain) != from_reg:
        esp = esp_for_host(rp_domain)
        if esp:
            flag("info", "H-RP-ESP", "Return-Path is an ESP bounce address", f"{rp_addr} ({esp}) — normal for bulk/marketing mail; SPF aligns to the ESP, not the brand.", 2)
        else:
            flag("medium", "H-RP-MISMATCH", "Return-Path domain ≠ From domain",
                 f"Bounces go to {rp_domain}; the envelope sender is not the displayed sender. SPF was evaluated on {rp_domain}.", 9)

    # From domain analysis
    if from_domain:
        bm = brand_match(from_domain)
        if bm and bm[1] in ("lookalike", "keyword", "subdomain_abuse"):
            flag("critical", "H-FROM-LOOKALIKE", f"Sender domain impersonates {bm[0]}",
                 f"{from_domain} is a {bm[1].replace('_', ' ')} of {bm[2]} — the genuine brand does not send from this domain.", 30)
        try:
            from_domain.encode("ascii")
        except UnicodeEncodeError:
            flag("high", "H-IDN", "Internationalised (IDN) sender domain", f"{from_domain} contains non-ASCII characters — possible homograph attack.", 18)
        if from_domain.startswith("xn--") or ".xn--" in from_domain:
            flag("high", "H-PUNYCODE", "Punycode sender domain", f"{from_domain} — homograph attack indicator.", 18)
        # org lookalike
        for od in org_domains:
            if from_reg != od and (levenshtein(domain_label(from_reg), domain_label(od)) <= 2 or normalize_homoglyphs(domain_label(from_reg)) == domain_label(od)):
                flag("critical", "H-ORG-LOOKALIKE", "Sender domain is a lookalike of YOUR organisation",
                     f"{from_domain} ≈ {od}. Targeted impersonation of the institution.", 32)

    # Timeline anomalies
    prev = None
    for h in reversed(hops):  # origin -> recipient
        ts = h.get("_ts")
        if ts and prev and ts < prev - __import__("datetime").timedelta(minutes=5):
            flag("medium", "H-TIME-TRAVEL", "Received timestamps go backwards",
                 f"Hop {h['position']} is stamped {int((prev - ts).total_seconds())}s earlier than the previous hop — forged/injected Received line or badly skewed clock.", 8)
            break
        if ts: prev = ts
    if date_hdr and hops and hops[0].get("_ts"):
        try:
            d = email.utils.parsedate_to_datetime(date_hdr)
            if d.tzinfo is None: d = d.replace(tzinfo=timezone.utc)
            delta = (hops[0]["_ts"] - d).total_seconds()
            if delta > 3600 * 6:
                flag("low", "H-DATE-SKEW", "Date header far earlier than delivery", f"{int(delta/3600)} h gap between Date and final Received — scheduled bulk send or forged Date.", 3)
            elif delta < -900:
                flag("medium", "H-DATE-FUTURE", "Date header is in the future relative to delivery", f"Date is {int(-delta/60)} min after final Received.", 6)
        except Exception:
            pass

    # Relay anomalies
    for h in hops:
        if h.get("helo_is_ip") and h.get("trust") in ("origin", "trusted"):
            flag("medium", "H-HELO-IP", "HELO identity is a bare IP address", f"Hop {h['position']}: from {h['from_host']} — misconfigured or throwaway sending host.", 7)
        if h.get("from_rdns") == "unknown" and h.get("trust") == "origin":
            flag("medium", "H-NO-RDNS", "Origin host has no reverse DNS", f"{h.get('from_ip')} has no PTR record — typical of compromised endpoints / rented VPS used for spam.", 8)
        if h.get("trust") == "origin" and not h.get("tls"):
            flag("low", "H-NO-TLS", "Origin hop delivered without TLS", "Plain SMTP into the first trusted receiver.", 3)
        if h.get("trust") == "origin" and h.get("from_host") and h.get("from_rdns") and h["from_rdns"] not in ("unknown",) and \
                registered_domain(h["from_host"]) != registered_domain(h["from_rdns"]) and not valid_ip(h["from_host"]):
            flag("medium", "H-HELO-RDNS", "HELO name does not match reverse DNS",
                 f"HELO {h['from_host']} vs PTR {h['from_rdns']} — sender is announcing a false identity to the MTA.", 9)
    if origin.get("origin_kind") == "earliest_public_relay" and from_reg and hops:
        oh = origin["origin_hop"]
        # direct-to-MX from a residential/hosting IP while claiming a domain hosted on ESP => spoof
        if oh and oh.get("from_esp") is None and from_reg in FREEMAIL:
            flag("high", "H-FREEMAIL-NOT-VIA-PROVIDER", f"Claims to be {from_reg} but did not come from {from_reg} servers",
                 f"Origin {origin_ip} is not {from_reg} infrastructure. Header From is forged.", 22)
    if len(hops) > 8:
        flag("low", "H-LONG-CHAIN", "Unusually long relay chain", f"{len(hops)} Received hops — forwarding loops or relay laundering.", 4)

    # X-Mailer / bulk tool artefacts
    xm = str(x_mailer).lower()
    if xm and any(t in xm for t in ("phpmailer", "swiftmailer", "python", "smtplib", "sendblaster", "mass", "bulk", "atomic", "turbo", "gammadyne", "mailer daemon", "nodemailer", "go-mail", "mailbee")):
        flag("medium", "H-XMAILER", "Scripted / bulk mailer signature", f"X-Mailer: {x_mailer}", 8)
    if msg.get("X-PHP-Originating-Script") or msg.get("X-PHP-Script"):
        flag("high", "H-PHP-SCRIPT", "Sent by a PHP script on a web server",
             f"{msg.get('X-PHP-Originating-Script') or msg.get('X-PHP-Script')} — typical of compromised websites used as mail cannons.", 12)
    prec = (msg.get("Precedence") or "").lower()
    if prec == "bulk" or msg.get("List-Unsubscribe"):
        flag("info", "H-BULK", "Bulk / list mail markers present", "Precedence: bulk or List-Unsubscribe — marketing infrastructure. Legit for newsletters, suspicious for 'personal' or 'security' mail.", 2)
    if to_hdr and ("undisclosed" in to_hdr.lower() or (from_addr and from_addr in to_hdr.lower())):
        flag("low", "H-TO-UNDISCLOSED", "Recipients hidden / To = From", f"To: {to_hdr[:80]}", 4)

    # ----- Live authentication -----
    auth_hdr = parse_auth_results(msg)
    dkim_sigs = parse_dkim_sigs(msg)
    live = {"spf": None, "spf_detail": "", "dkim": None, "dkim_detail": "", "dmarc": None, "dmarc_policy": None, "dmarc_detail": "", "mx": [], "spf_record": None, "dmarc_record": None}
    spf_domain = rp_domain or from_domain
    if do_dns and from_domain:
        try:
            spf_res = intel.check_spf(origin_ip, spf_domain) if origin_ip else {"result": "none", "detail": "no origin IP"}
            live["spf"], live["spf_detail"], live["spf_record"] = spf_res["result"], spf_res["detail"], spf_res.get("record")
        except Exception as e:
            live["spf_detail"] = f"error: {e}"
        try:
            dm = intel.get_dmarc(from_reg)
            live["dmarc_record"] = dm.get("record"); live["dmarc_policy"] = dm.get("policy")
        except Exception:
            pass
        try:
            live["mx"] = intel.get_mx(from_reg)
        except Exception:
            pass
    # DKIM
    dkim_ok = verify_dkim(raw, dkim_sigs) if (dkim_sigs and do_dns) else None
    dkim_aligned = any(registered_domain(s["d"]) == from_reg for s in dkim_sigs)
    if dkim_sigs:
        live["dkim"] = "pass" if dkim_ok else ("fail" if dkim_ok is False else "unverified")
        live["dkim_detail"] = f"{len(dkim_sigs)} signature(s): " + ", ".join(f"d={s['d']} s={s['s']}" for s in dkim_sigs)
        if dkim_ok is None:
            live["dkim_detail"] += " — public key not retrievable (selector not published / offline); relying on receiver's Authentication-Results if present"
    else:
        live["dkim"] = "none"; live["dkim_detail"] = "No DKIM-Signature header"

    # Effective verdicts: prefer receiver's Authentication-Results if present, else live check
    eff_spf = auth_hdr["spf"] or live["spf"] or "none"
    eff_dkim = auth_hdr["dkim"] or live["dkim"] or "none"
    if eff_dkim == "unverified":
        eff_dkim = "unverified"
    spf_aligned = eff_spf == "pass" and registered_domain(spf_domain) == from_reg
    dkim_pass_aligned = eff_dkim == "pass" and dkim_aligned
    evaluable = bool(auth_hdr["spf"] or auth_hdr["dkim"] or origin_ip or dkim_sigs)
    if auth_hdr["dmarc"]:
        eff_dmarc = auth_hdr["dmarc"]
    elif not evaluable:
        eff_dmarc = "unverifiable"
        eff_spf = "unverifiable" if eff_spf == "none" else eff_spf
    else:
        eff_dmarc = "pass" if (spf_aligned or dkim_pass_aligned) else ("fail" if live["dmarc_record"] else "none")
    policy = live["dmarc_policy"]
    auth = {"spf": eff_spf, "spf_domain": spf_domain, "spf_aligned": spf_aligned, "dkim": eff_dkim, "dkim_domains": [s["d"] for s in dkim_sigs],
            "dkim_aligned": dkim_aligned, "dkim_crypto_verified": dkim_ok, "dmarc": eff_dmarc, "dmarc_policy": policy, "arc": auth_hdr["arc"],
            "receiver_auth_results": auth_hdr["raw"][:3], "live": live}

    if eff_spf in ("fail", "softfail"):
        flag("high" if eff_spf == "fail" else "medium", "A-SPF-FAIL", f"SPF {eff_spf}", f"{origin_ip or 'origin'} is not authorised to send for {spf_domain}. {live['spf_detail'] or ''}".strip(), 20 if eff_spf == "fail" else 12)
    elif eff_spf == "unverifiable":
        flag("low", "A-UNVERIFIABLE", "Authentication could not be evaluated", "No originating IP or receiver Authentication-Results available — SPF/DMARC verdicts are unknown, not failed.", 2)
    elif eff_spf == "none" and from_reg and from_reg not in FREEMAIL and not live["spf_record"]:
        flag("medium", "A-SPF-NONE", "No SPF record published", f"{spf_domain} publishes no SPF — anyone can send as this domain.", 8)
    elif eff_spf == "none" and from_reg and from_reg not in FREEMAIL:
        flag("low", "A-SPF-NOEVAL", "SPF not evaluated", f"{spf_domain} publishes SPF but no client IP was available to test against it.", 2)
    elif eff_spf == "pass" and not spf_aligned:
        flag("medium", "A-SPF-UNALIGNED", "SPF passes but for a different domain than From",
             f"SPF authorised {spf_domain}, while the user sees {from_domain}. DMARC would not accept this SPF result.", 8)
    if eff_dkim == "fail":
        flag("high", "A-DKIM-FAIL", "DKIM signature invalid", "Body or headers were modified after signing, or the signature is forged.", 16)
    elif eff_dkim == "none" and from_reg not in FREEMAIL and from_reg and not fragment:
        flag("medium", "A-DKIM-NONE", "No DKIM signature", "Message is not cryptographically bound to the sender domain.", 8)
    elif eff_dkim == "unverified":
        flag("low", "A-DKIM-UNVERIFIED", "DKIM signature could not be verified", f"Selector key not published in DNS for {', '.join(auth['dkim_domains'])} — signature is unverifiable and gives no assurance.", 5)
    elif eff_dkim == "pass" and dkim_sigs and not dkim_aligned:
        flag("medium", "A-DKIM-UNALIGNED", "DKIM signed by a third-party domain",
             f"Signed by {', '.join(auth['dkim_domains'])}, not {from_reg}. Fine for ESPs, suspicious for 'security' mail.", 6)
    if eff_dmarc == "fail":
        pol = policy or "none"
        flag("critical" if pol in ("reject", "quarantine") else "high", "A-DMARC-FAIL", f"DMARC fail (domain policy p={pol})",
             f"Neither SPF nor DKIM aligned with {from_reg}. " + ("Domain owner asked receivers to REJECT such mail — this is a spoof." if pol == "reject" else "Domain owner asked for quarantine." if pol == "quarantine" else "Domain has a monitor-only policy, so spoofs are delivered."), 26 if pol in ("reject", "quarantine") else 18)
    elif eff_dmarc == "none" and from_reg and from_reg not in FREEMAIL:
        flag("low", "A-DMARC-NONE", "Sender domain publishes no DMARC", f"{from_reg} cannot be protected from spoofing by receivers.", 5)
    elif eff_dmarc == "pass":
        flag("info", "A-DMARC-PASS", "DMARC pass", f"Sender authenticated as {from_reg}. If the mail is malicious, the ACCOUNT or the DOMAIN itself is the problem (compromised account / attacker-owned domain).", 0)

    # ARC
    if msg.get("ARC-Seal") and auth_hdr["arc"] == "pass":
        flag("info", "A-ARC", "ARC chain present", "Message was forwarded through an intermediary that preserved auth results.", 0)

    hop_out = []
    for h in hops:
        hop_out.append({k: v for k, v in h.items() if not k.startswith("_")})
    return {
        "from": {"name": from_name, "address": from_addr, "domain": from_domain, "registered_domain": from_reg, "raw": frm},
        "reply_to": {"name": rt_name, "address": rt_addr, "domain": rt_domain, "raw": reply_to},
        "return_path": {"address": rp_addr, "domain": rp_domain},
        "to": to_hdr, "subject": subject, "message_id": msgid, "date": date_hdr, "x_mailer": str(x_mailer), "x_originating_ip": x_orig_ip,
        "hops": hop_out, "origin": {k: (v if k != "origin_hop" else ({kk: vv for kk, vv in v.items() if not kk.startswith("_")} if v else None)) for k, v in origin.items()},
        "auth": auth, "findings": findings, "timing_ms": int((time.time() - t0) * 1000), "_msg": msg,
    }
