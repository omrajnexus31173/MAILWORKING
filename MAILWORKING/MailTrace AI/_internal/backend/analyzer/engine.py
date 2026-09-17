"""
Pipeline orchestrator + risk scoring + origin attribution.

Score model: weighted evidence accumulation with diminishing returns per category
(so 12 weak content cues cannot outrank one hard DMARC-reject spoof) followed by
a calibrated squash to 0-100. Verdict thresholds are configurable.
"""
import time, hashlib, math, json, uuid, re
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor

from . import header_forensics, content, intel
from .common import registered_domain, FREEMAIL, load_org_profile, is_private_ip, ESP_ALL, esp_for_host, brand_match, domain_label, levenshtein, normalize_homoglyphs

SEV_CAP = {"critical": 40, "high": 30, "medium": 18, "low": 8, "info": 0}

def _category_score(findings: List[Dict[str, Any]]) -> float:
    """Sum weights with diminishing returns: first finding full, then 70%, 50%, 35%..."""
    ws = sorted([f["weight"] for f in findings if f["weight"] > 0], reverse=True)
    total, mult = 0.0, 1.0
    for w in ws:
        total += w * mult
        mult *= 0.7
    return total

CONTEXT_CUES = {"C-NLP-AUTHORITY", "C-NLP-GENERIC_GREETING", "C-NLP-CLICK_LURE", "C-NLP-POOR_LANGUAGE", "C-NLP-DELIVERY", "C-NLP-REWARD"}
PRIMARY_CUES = {"C-NLP-URGENCY", "C-NLP-THREAT", "C-NLP-CREDENTIAL", "C-NLP-FINANCIAL", "C-NLP-SECRECY", "C-NLP-AVAILABILITY", "C-NLP-PASSWORD_RESET", "C-BEC", "C-CRYPTO", "C-UPI"}

def compute_score(hdr_findings, content_findings, infra_findings, ml_prob=None, trust: Dict[str, Any] = None) -> Dict[str, Any]:
    trust = trust or {}
    # contextual cues (authority, greeting...) only count when a primary social-engineering cue is present
    has_primary = any(f["code"] in PRIMARY_CUES for f in content_findings)
    for f in content_findings:
        if f["code"] in CONTEXT_CUES and not has_primary:
            f["weight"] = min(f["weight"], 2)
    cats = {"identity_auth": [f for f in hdr_findings if f["code"].startswith("A-") or f["code"].startswith("H-")],
            "content": [f for f in content_findings if not f["code"].startswith("C-URL") and not f["code"].startswith("C-ATT")],
            "links_attachments": [f for f in content_findings if f["code"].startswith("C-URL") or f["code"].startswith("C-ATT")],
            "infrastructure": infra_findings}
    raw = {k: _category_score(v) for k, v in cats.items()}
    # ML probability modulates the heuristic content score (counter-evidence when the model is confident it's benign)
    ml_factor = 1.0
    if ml_prob is not None:
        if ml_prob < 0.10: ml_factor = 0.45
        elif ml_prob < 0.25: ml_factor = 0.65
        elif ml_prob > 0.85: ml_factor = 1.15
    raw["content"] *= ml_factor
    # trust credits: only ever reduce the *content* category — hard identity / link / attachment evidence is never discounted
    credit = 0.0
    credits = []
    if trust.get("dmarc_pass") and trust.get("domain_age_days", 0) > 365 and not trust.get("freemail"):
        credit += 10; credits.append(f"DMARC-aligned mail from {trust.get('domain')} (registered {trust['domain_age_days']//365}+ yrs ago)")
    if trust.get("partner"):
        credit += 12; credits.append("Sender domain is a configured trusted partner")
    if trust.get("known_esp_transactional"):
        credit += 6; credits.append("Authenticated transactional mail via known ESP")
    raw["content"] = max(0.0, raw["content"] - credit)
    total_raw = sum(raw.values())
    # squash: 0 -> 0 ; 30 -> ~45 ; 60 -> ~75 ; 100 -> ~92
    score = 100 * (1 - math.exp(-total_raw / 45.0))
    # hard floors: DMARC fail with reject/quarantine + lookalike => at least 80
    codes = {f["code"] for f in hdr_findings + content_findings + infra_findings}
    if "H-FROM-LOOKALIKE" in codes or "H-ORG-LOOKALIKE" in codes:
        score = max(score, 78)
    if "A-DMARC-FAIL" in codes and any(f["code"] == "A-DMARC-FAIL" and "REJECT" in f["detail"] for f in hdr_findings):
        score = max(score, 75)
    crit = sum(1 for f in hdr_findings + content_findings + infra_findings if f["severity"] == "critical")
    if crit >= 2:
        score = max(score, 85)
    score = round(min(99, score), 1)
    if score >= 80: verdict, label = "malicious", "Phishing / Fraud"
    elif score >= 60: verdict, label = "likely_malicious", "Likely Phishing"
    elif score >= 35: verdict, label = "suspicious", "Suspicious"
    elif score >= 15: verdict, label = "low_risk", "Low Risk"
    else: verdict, label = "clean", "Clean"
    return {"score": score, "verdict": verdict, "label": label, "category_raw": {k: round(v, 1) for k, v in raw.items()},
            "category_pct": {k: round(min(100, 100 * (1 - math.exp(-v / 30.0)))) for k, v in raw.items()},
            "ml_factor": ml_factor, "trust_credits": credits}

def classify_threat(hdr, cont, score) -> Dict[str, Any]:
    """Map evidence to a threat type & BEC sub-type."""
    codes = {f["code"] for f in hdr["findings"] + cont["findings"]}
    bec = list(cont["features"]["bec_patterns"].keys())
    types = []
    if score["verdict"] in ("clean", "low_risk"):
        return {"primary": "legitimate", "secondary": [], "bec": bec}
    if "H-FROM-LOOKALIKE" in codes or "H-ORG-LOOKALIKE" in codes or "H-DN-BRAND" in codes or "H-DN-EMAIL" in codes:
        types.append("impersonation")
    if "A-DMARC-FAIL" in codes or "A-SPF-FAIL" in codes or "H-FREEMAIL-NOT-VIA-PROVIDER" in codes:
        types.append("spoofing")
    if "Credential harvesting" in bec or "C-NLP-CREDENTIAL" in codes or "C-NLP-PASSWORD_RESET" in codes or any(u.get("brand") for u in cont["urls"]["urls"]):
        types.append("credential_phishing")
    if any(b in bec for b in ("Payment diversion / invoice fraud", "Executive impersonation / CEO fraud", "Gift card scam", "Payroll / salary diversion", "Vendor / supplier impersonation")):
        types.append("business_email_compromise")
    if cont["attachments"]["max_risk"] >= 30:
        types.append("malware_delivery")
    if "Sextortion / blackmail" in bec or "C-CRYPTO" in codes:
        types.append("extortion")
    if any(b in bec for b in ("Job / scholarship / loan scam", "Government / tax impersonation")) or "C-NLP-REWARD" in codes:
        types.append("advance_fee_fraud")
    if not types:
        types.append("phishing" if score["verdict"] != "suspicious" else "suspicious")
    return {"primary": types[0], "secondary": types[1:], "bec": bec}

def _tz_offset_of(ts_iso: str):
    if not ts_iso: return None
    m = re.search(r"([+-])(\d{2}):(\d{2})$", ts_iso)
    if not m: return None
    sign = 1 if m.group(1) == "+" else -1
    return sign * (int(m.group(2)) * 60 + int(m.group(3)))

def _tz_consistency(origin_hop: Dict[str, Any], g: Dict[str, Any]):
    """Compare the origin MTA's clock offset with the geolocated timezone (a classic header-forensics cross-check)."""
    off = _tz_offset_of(origin_hop.get("timestamp") or "")
    tz = g.get("timezone")
    if off is None or not tz:
        return None
    try:
        from zoneinfo import ZoneInfo
        from datetime import datetime
        geo_off = int(datetime.now(ZoneInfo(tz)).utcoffset().total_seconds() // 60)
    except Exception:
        return None
    diff = abs(geo_off - off)
    def fmt(m): return f"{'+' if m >= 0 else '-'}{abs(m)//60:02d}:{abs(m)%60:02d}"
    if diff >= 120:
        return (f"Origin server clock is set to UTC{fmt(off)} but the geolocated IP sits in {tz} (UTC{fmt(geo_off)}) — the operator/server is likely located elsewhere or the IP is proxied", 0.75)
    return (f"Origin server clock offset UTC{fmt(off)} is consistent with geolocated timezone {tz}", 1.0)

def attribute_origin(hdr, geo: Dict[str, Any], dom_intel: Dict[str, Any], score) -> Dict[str, Any]:
    """
    Decide the most likely sending scenario:
      compromised_account | attacker_owned_lookalike_domain | direct_spoof | anonymised_infra | bulk_esp_abuse | legitimate
    and produce an origin confidence.
    """
    auth = hdr["auth"]; origin = hdr["origin"]; from_reg = hdr["from"]["registered_domain"]
    codes = {f["code"] for f in hdr["findings"]}
    oip = origin.get("origin_ip")
    g = geo.get(oip, {}) if oip else {}
    tags = g.get("tags", [])
    dmarc_pass = auth["dmarc"] == "pass"
    scenario, conf, reasons = "undetermined", 0.3, []
    if score["verdict"] in ("clean", "low_risk"):
        scenario, conf = "legitimate", 0.8
        reasons.append("Low risk score; authentication " + ("passed" if dmarc_pass else "not conclusive"))
    elif "H-FROM-LOOKALIKE" in codes or "H-ORG-LOOKALIKE" in codes or (dom_intel.get("age_days") is not None and dom_intel["age_days"] < 90):
        scenario, conf = "attacker_owned_lookalike_domain", 0.75
        reasons.append("Sender domain is a brand/organisation lookalike" if ("H-FROM-LOOKALIKE" in codes or "H-ORG-LOOKALIKE" in codes) else f"Sender domain registered only {dom_intel.get('age_days')} days ago")
        if dmarc_pass: reasons.append("DMARC passes — attacker controls the domain's DNS/mail, not a spoof"); conf += 0.1
    elif dmarc_pass and from_reg in FREEMAIL:
        scenario, conf = "freemail_account", 0.8
        reasons.append(f"Authenticated {from_reg} account — actor registered/uses a free webmail account; provider holds registration + login IP logs (legal request)")
    elif dmarc_pass and from_reg and from_reg not in FREEMAIL:
        scenario, conf = "compromised_account", 0.7
        reasons.append(f"Mail authenticated as {from_reg} (SPF/DKIM aligned) yet content is malicious → the mailbox or tenant is compromised, or an insider")
        if origin.get("origin_kind") == "authenticated_submission":
            reasons.append(f"Submission IP {oip} is the attacker's client, not the domain's server"); conf += 0.1
    elif origin.get("origin_kind") == "authenticated_submission" and (origin.get("origin_hop") or {}).get("by_host") and \
            registered_domain((origin.get("origin_hop") or {}).get("by_host") or "") == from_reg:
        scenario, conf = "compromised_account", 0.65
        reasons.append(f"Message was submitted with a valid login (ESMTPSA) to the sender's own mail server {(origin.get('origin_hop') or {}).get('by_host')} from {oip} — either the vendor mailbox is compromised or the domain is attacker-run")
        reasons.append(f"Login IP {oip} ({g.get('isp')}, {g.get('city')}, {g.get('country')}) is the strongest attribution artefact: request auth logs from the mail server operator")
    elif auth["dmarc"] == "fail" or auth["spf"] in ("fail", "softfail") or "H-FREEMAIL-NOT-VIA-PROVIDER" in codes:
        scenario, conf = "direct_spoof", 0.75
        reasons.append("Header From is forged: authentication failed for the displayed domain")
        if "TOR_EXIT" in tags or "PROXY/VPN" in tags or "VPN_PROVIDER" in tags:
            scenario = "anonymised_infra"; reasons.append(f"Origin {oip} is {g.get('category')} — actor hid the true location")
        elif "HOSTING/CLOUD" in tags or "BULLETPROOF_SUSPECT" in tags:
            reasons.append(f"Sent from rented server at {g.get('isp')} ({g.get('country')}) — VPS mail cannon; abuse contact can identify the customer")
        elif tags and tags[0] in ("MOBILE/RESIDENTIAL", "RESIDENTIAL/ISP"):
            reasons.append(f"Origin is a residential/mobile IP at {g.get('isp')} — likely infected/botnet host or the actor's own connection; ISP subscriber lookup possible")
    elif esp_for_host((origin.get("origin_hop") or {}).get("from_host") or "") or "EMAIL_PROVIDER" in tags:
        scenario, conf = "bulk_esp_abuse", 0.6
        reasons.append("Sent via a commercial ESP/marketing platform — ESP account holder can be identified by the ESP")
    else:
        reasons.append("Insufficient authentication evidence to determine scenario")
    if oip and ("TOR_EXIT" in tags or "PROXY/VPN" in tags or "VPN_PROVIDER" in tags):
        conf = min(conf, 0.55)
    if "EMAIL_PROVIDER" in tags:
        reasons.append(f"Origin IP {oip} belongs to the email provider ({g.get('isp')}); the submitting client's IP is withheld by the provider and is obtainable through a lawful request (login/audit logs)")
    loc_conf = origin.get("confidence", 0.2)
    if g.get("status") in ("success", "seed"):
        if g.get("anonymity_score", 0) >= 0.7: loc_conf *= 0.35
        elif g.get("anonymity_score", 0) >= 0.4: loc_conf *= 0.75
    else:
        loc_conf *= 0.5
    # multi-source consistency: geo country vs RIR registry country vs clock timezone of origin hop
    consistency = []
    reg_country = (hdr.get("_ip_registry") or {}).get("country")
    if reg_country and g.get("countryCode") and reg_country.upper() != g.get("countryCode"):
        consistency.append(f"GeoIP says {g.get('countryCode')} but the RIR netblock registration says {reg_country} — IP is leased/announced away from its registered region")
        loc_conf *= 0.8
    tz_note = _tz_consistency(origin.get("origin_hop") or {}, g)
    if tz_note:
        consistency.append(tz_note[0]); loc_conf *= tz_note[1]
    reasons += consistency
    pretty = {"compromised_account": "Compromised legitimate account", "attacker_owned_lookalike_domain": "Attacker-registered lookalike domain",
              "direct_spoof": "Direct header spoofing", "anonymised_infra": "Anonymised infrastructure (Tor/VPN/proxy)", "bulk_esp_abuse": "Abuse of bulk email service",
              "freemail_account": "Free webmail account", "legitimate": "Legitimate sender", "undetermined": "Undetermined"}
    return {"scenario": scenario, "scenario_label": pretty[scenario], "confidence": round(min(0.95, conf), 2), "location_confidence": round(min(0.95, loc_conf), 2),
            "reasons": reasons, "origin_ip": oip, "origin_geo": {k: g.get(k) for k in ("country", "countryCode", "regionName", "city", "isp", "org", "as", "lat", "lon", "category", "tags", "reverse", "timezone")} if g else None}

def infra_findings_from(geo: Dict[str, Any], hdr, dom_intel: Dict[str, Any], url_dom_intel: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    def flag(sev, code, title, detail, weight): out.append({"severity": sev, "code": code, "title": title, "detail": detail, "weight": weight})
    oip = hdr["origin"].get("origin_ip")
    g = geo.get(oip) if oip else None
    from_reg = hdr["from"]["registered_domain"]
    if g and g.get("status") in ("success", "seed"):
        tags = g.get("tags", [])
        if "TOR_EXIT" in tags: flag("high", "I-TOR", "Origin IP is a Tor exit node", f"{oip} — sender deliberately anonymised.", 20)
        elif "PROXY/VPN" in tags or "VPN_PROVIDER" in tags: flag("medium", "I-VPN", "Origin IP is a VPN / proxy", f"{oip} ({g.get('isp')}) — location is masked.", 12)
        if "BULLETPROOF_SUSPECT" in tags: flag("high", "I-BULLETPROOF", "Origin in abuse-tolerant hosting", f"{g.get('isp')} ({g.get('country')}) is frequently associated with malicious mail.", 15)
        elif "HOSTING/CLOUD" in tags and from_reg and from_reg in FREEMAIL: flag("high", "I-HOSTING-FREEMAIL", "Freemail sender from a rented server", f"{oip} at {g.get('isp')} — {from_reg} never sends from third-party servers.", 16)
        elif "HOSTING/CLOUD" in tags and hdr["auth"]["dmarc"] != "pass" and esp_for_host(g.get("reverse") or "") is None:
            flag("medium", "I-HOSTING", "Unauthenticated mail from a cloud/VPS server", f"{oip} ({g.get('isp')}, {g.get('city')}, {g.get('country')})", 8)
        if hdr["from"]["domain"].endswith(".gov.in") or hdr["from"]["domain"].endswith(".nic.in") or hdr["from"]["domain"].endswith(".ac.in"):
            if g.get("countryCode") not in ("IN", None, "--") and hdr["auth"]["dmarc"] != "pass":
                flag("high", "I-GEO-MISMATCH", "Indian government / academic sender from foreign IP", f"Claims {hdr['from']['domain']} but originated in {g.get('country')}.", 15)
    if dom_intel.get("found"):
        age = dom_intel.get("age_days")
        if age is not None:
            if age < 30: flag("critical", "I-DOM-NEW", "Sender domain registered < 30 days ago", f"{dom_intel['domain']} created {dom_intel.get('created','')[:10]} via {dom_intel.get('registrar','?')}", 24)
            elif age < 180: flag("high", "I-DOM-YOUNG", "Sender domain registered < 6 months ago", f"{dom_intel['domain']} created {dom_intel.get('created','')[:10]} ({age} days)", 12)
        if dom_intel.get("privacy_proxy") and from_reg not in FREEMAIL and age is not None and age < 365:
            flag("low", "I-DOM-PRIVACY", "WHOIS privacy on young domain", "Registrant identity redacted.", 3)
    elif from_reg and from_reg not in FREEMAIL and not dom_intel.get("resolves", True):
        flag("high", "I-DOM-NX", "Sender domain does not resolve", f"{from_reg} has no A/MX records — non-existent or parked domain used as forged From.", 14)
    if hdr["auth"]["live"].get("mx") == [] and from_reg and from_reg not in FREEMAIL and dom_intel.get("found") and not intel.OFFLINE:
        flag("medium", "I-NO-MX", "Sender domain has no MX record", f"{from_reg} cannot receive replies — one-way phishing domain.", 8)
    for d, di in url_dom_intel.items():
        if di.get("found") and di.get("age_days") is not None and di["age_days"] < 60:
            flag("high", "I-URL-DOM-NEW", f"Link domain {d} registered {di['age_days']} days ago", f"Registrar: {di.get('registrar','?')}", 14)
    return out

def build_graph(result: Dict[str, Any]) -> Dict[str, Any]:
    nodes, edges = {}, []
    def n(id_, typ, label=None, **kw):
        if id_ not in nodes: nodes[id_] = {"id": id_, "type": typ, "label": label or id_, **kw}
        return id_
    def e(a, b, rel): edges.append({"source": a, "target": b, "rel": rel})
    h = result["headers"]
    em = n("email:" + result["id"], "email", result["headers"]["subject"][:40] or "(no subject)", score=result["score"]["score"])
    if h["from"]["address"]:
        s = n("addr:" + h["from"]["address"], "sender", h["from"]["address"]); e(em, s, "from")
        if h["from"]["registered_domain"]:
            d = n("domain:" + h["from"]["registered_domain"], "domain", h["from"]["registered_domain"]); e(s, d, "belongs_to")
    if h["reply_to"]["address"] and h["reply_to"]["address"] != h["from"]["address"]:
        r = n("addr:" + h["reply_to"]["address"], "reply_to", h["reply_to"]["address"]); e(em, r, "reply_to")
    if h["return_path"]["address"] and h["return_path"]["domain"] != h["from"]["domain"]:
        r = n("addr:" + h["return_path"]["address"], "return_path", h["return_path"]["address"]); e(em, r, "return_path")
    for hop in h["hops"]:
        if hop.get("from_ip") and not is_private_ip(hop["from_ip"]):
            g = result["geo"].get(hop["from_ip"], {})
            ip = n("ip:" + hop["from_ip"], "ip", hop["from_ip"], country=g.get("countryCode"), isp=g.get("isp"), trust=hop.get("trust"))
            e(em, ip, "relayed_via" if hop.get("trust") != "origin" else "originated_from")
            if g.get("as"):
                a = n("asn:" + g["as"].split()[0], "asn", g["as"][:40]); e(ip, a, "announced_by")
    for u in result["content"]["urls"]["urls"][:10]:
        if u.get("registered_domain"):
            d = n("domain:" + u["registered_domain"], "url_domain", u["registered_domain"], risk=u["risk"]); e(em, d, "links_to")
    for a in result["content"]["attachments"]["attachments"]:
        f = n("file:" + a["sha256"][:12], "attachment", a["filename"], sha256=a["sha256"]); e(em, f, "attaches")
    for w in result["content"]["features"].get("crypto_wallets", []):
        c = n("wallet:" + w, "wallet", w[:16] + "…"); e(em, c, "requests_payment_to")
    for p in result["content"]["features"].get("phone_numbers", [])[:3]:
        c = n("phone:" + p, "phone", p); e(em, c, "mentions")
    for u in result["content"]["features"].get("upi_ids", [])[:3]:
        c = n("upi:" + u, "upi", u); e(em, c, "requests_payment_to")
    return {"nodes": list(nodes.values()), "edges": edges}

def analyze_email(raw: bytes, org_profile: Dict[str, Any] = None, do_dns: bool = True, live: bool = True) -> Dict[str, Any]:
    """
    live=True  : full analysis (live SPF/DKIM/DMARC, GeoIP, RDAP, PTR) — 1-9 s for never-seen infrastructure.
    live=False : *triage pass* — identical parsing, header forensics on recorded Authentication-Results, NLP, URL and
                 attachment analysis, cached/seeded GeoIP only; no network round-trips (~20-60 ms). Bulk ingestion runs
                 this first on every message so provisional scores exist within seconds, then enriches worst-first.
    """
    t0 = time.time()
    if not live:
        do_dns = False
    org = org_profile or load_org_profile()
    org_domains = [d.lower() for d in org.get("domains", [])]
    vips = org.get("vips", [])
    hdr = header_forensics.analyze_headers(raw, org_domains, do_dns=do_dns)
    msg = hdr.pop("_msg")
    cont = content.analyze_content(msg, hdr["subject"], hdr["from"]["registered_domain"], org_domains, vips)

    # VIP impersonation
    fn = (hdr["from"]["name"] or "").lower()
    for v in vips:
        vn = v.get("name", "").lower(); vmail = v.get("email", "").lower()
        if vn and fn and (vn in fn or levenshtein(vn, fn) <= 2) and hdr["from"]["address"] != vmail:
            hdr["findings"].append({"severity": "critical", "code": "H-VIP-IMPERSONATION", "title": f"Impersonates {v.get('name')} ({v.get('role','VIP')})",
                                    "detail": f"Display name matches a protected executive but address is {hdr['from']['address']} (expected {vmail}).", "weight": 30})
    # internal spoof: From is our domain but DMARC not pass
    if hdr["from"]["registered_domain"] in org_domains and hdr["auth"]["dmarc"] not in ("pass", "unverifiable"):
        hdr["findings"].append({"severity": "critical", "code": "H-INTERNAL-SPOOF", "title": "Claims to be from YOUR domain but fails authentication",
                                "detail": f"{hdr['from']['address']} did not authenticate as {hdr['from']['registered_domain']}.", "weight": 28})

    # ---- enrichment (parallel) ----
    ips = [h["from_ip"] for h in hdr["hops"] if h.get("from_ip")]
    if hdr.get("x_originating_ip"): ips.append(hdr["x_originating_ip"])
    ips = list(dict.fromkeys(ips))
    from_reg = hdr["from"]["registered_domain"]
    url_domains = [d for d in cont["urls"]["domains"] if d and d not in ESP_ALL and d != from_reg][:4]
    with ThreadPoolExecutor(max_workers=8) as ex:
        f_geo = ex.submit(intel.geolocate, ips, live)
        f_dom = ex.submit(intel.domain_rdap, from_reg) if from_reg and from_reg not in FREEMAIL and do_dns else None
        f_rt = ex.submit(intel.domain_rdap, hdr["reply_to"]["domain"]) if hdr["reply_to"]["domain"] and registered_domain(hdr["reply_to"]["domain"]) not in FREEMAIL and registered_domain(hdr["reply_to"]["domain"]) != from_reg and do_dns else None
        f_urls = {d: ex.submit(intel.domain_rdap, d) for d in url_domains} if do_dns else {}
        geo = f_geo.result()
        dom_intel = f_dom.result() if f_dom else ({"domain": from_reg, "found": False, "freemail": True} if from_reg in FREEMAIL else {"domain": from_reg, "found": False})
        rt_intel = f_rt.result() if f_rt else None
        url_intel = {d: f.result() for d, f in f_urls.items()}
        oip = hdr["origin"].get("origin_ip")
        f_iprdap = ex.submit(intel.ip_rdap, oip) if oip and do_dns else None
        f_ptr = ex.submit(intel.get_ptr, oip) if oip and do_dns else None
        ip_reg = f_iprdap.result() if f_iprdap else {}
        ptr = f_ptr.result() if f_ptr else None
    if oip and oip in geo and ptr: geo[oip]["reverse"] = ptr
    hdr["_ip_registry"] = ip_reg
    infra = infra_findings_from(geo, hdr, dom_intel, url_intel)
    trust = {"dmarc_pass": hdr["auth"]["dmarc"] == "pass", "domain_age_days": dom_intel.get("age_days") or 0, "freemail": from_reg in FREEMAIL, "domain": from_reg,
             "partner": from_reg in [p.lower() for p in org.get("partners", [])] and hdr["auth"]["dmarc"] == "pass",
             "known_esp_transactional": hdr["auth"]["dmarc"] == "pass" and any(f["code"] == "H-BULK" for f in hdr["findings"]) and not cont["features"]["bec_patterns"]}
    score = compute_score(hdr["findings"], cont["findings"], infra, cont["nlp"].get("phishing_probability"), trust)
    threat = classify_threat(hdr, cont, score)
    attribution = attribute_origin(hdr, geo, dom_intel, score)
    hdr.pop("_ip_registry", None)
    all_findings = sorted(hdr["findings"] + cont["findings"] + infra, key=lambda f: (["critical", "high", "medium", "low", "info"].index(f["severity"]), -f["weight"]))

    # trace path for map: origin -> ... -> recipient
    path = []
    for h in reversed(hdr["hops"]):
        ip = h.get("from_ip")
        if not ip: continue
        g = geo.get(ip, {})
        path.append({"position": h["position"], "ip": ip, "host": h.get("from_host"), "rdns": h.get("from_rdns") or g.get("reverse"), "by": h.get("by_host"), "timestamp": h.get("timestamp"),
                     "country": g.get("country"), "countryCode": g.get("countryCode"), "city": g.get("city"), "region": g.get("regionName"), "isp": g.get("isp"), "asn": g.get("as"), "lat": g.get("lat"), "lon": g.get("lon"),
                     "tags": g.get("tags", []), "category": g.get("category"), "trust": h.get("trust"), "tls": h.get("tls"), "auth_submission": h.get("authenticated_submission"), "protocol": h.get("protocol"), "private": is_private_ip(ip)})
    # hop latencies
    prev_ts = None
    for p in path:
        p["delay_s"] = None
        if p["timestamp"]:
            from datetime import datetime
            ts = datetime.fromisoformat(p["timestamp"])
            if prev_ts is not None: p["delay_s"] = int((ts - prev_ts).total_seconds())
            prev_ts = ts

    eid = hashlib.sha256(raw).hexdigest()
    result = {
        "id": eid[:16], "sha256": eid, "size": len(raw), "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "org": org.get("organization"),
        "score": score, "threat": threat, "attribution": attribution, "headers": hdr, "content": cont, "geo": geo, "trace_path": path,
        "domain_intel": dom_intel, "reply_to_domain_intel": rt_intel, "url_domain_intel": url_intel, "origin_ip_registry": ip_reg,
        "findings": all_findings, "iocs": {
            "ips": [ip for ip in ips if not is_private_ip(ip)], "origin_ip": oip, "sender": hdr["from"]["address"], "reply_to": hdr["reply_to"]["address"] or None,
            "return_path": hdr["return_path"]["address"] or None, "domains": sorted(set([from_reg] + cont["urls"]["domains"]) - {""}),
            "urls": [u["url"] for u in cont["urls"]["urls"][:25]], "attachment_hashes": [{"name": a["filename"], "sha256": a["sha256"], "md5": a["md5"]} for a in cont["attachments"]["attachments"]],
            "crypto_wallets": cont["features"]["crypto_wallets"], "upi_ids": cont["features"]["upi_ids"], "phones": cont["features"]["phone_numbers"], "message_id": hdr["message_id"]},
        "timing_ms": int((time.time() - t0) * 1000), "offline": intel.OFFLINE, "analysis_depth": "full" if live else "triage",
    }
    result["graph"] = build_graph(result)
    result["summary"] = summarize(result)
    return result

def summarize(r: Dict[str, Any]) -> str:
    h, s, a, t = r["headers"], r["score"], r["attribution"], r["threat"]
    who = f'"{h["from"]["name"]}" <{h["from"]["address"]}>' if h["from"]["name"] else h["from"]["address"] or "unknown sender"
    top = [f["title"] for f in r["findings"] if f["severity"] in ("critical", "high")][:4]
    g = a.get("origin_geo") or {}
    loc = ", ".join(x for x in [g.get("city"), g.get("regionName"), g.get("country")] if x) or "unknown location"
    parts = [f"{s['label']} (risk {s['score']}/100). Message from {who} with subject \"{h['subject'][:80]}\"."]
    if t["primary"] != "legitimate":
        parts.append("Threat type: " + t["primary"].replace("_", " ") + (" + " + ", ".join(x.replace("_", " ") for x in t["secondary"]) if t["secondary"] else "") + ".")
    if top: parts.append("Key evidence: " + "; ".join(top) + ".")
    if a.get("origin_ip"):
        parts.append(f"Earliest reliable origin: {a['origin_ip']} ({g.get('isp') or 'unknown ISP'}) geolocated to {loc} [{g.get('category') or 'n/a'}], location confidence {int(a['location_confidence']*100)}%.")
    parts.append(f"Most likely scenario: {a['scenario_label']} (confidence {int(a['confidence']*100)}%).")
    return " ".join(parts)
