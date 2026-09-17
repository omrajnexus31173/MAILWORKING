"""
Content analysis: body extraction, NLP classifier, social-engineering cue detection,
URL forensics (lookalikes, obfuscation, redirects, shorteners, mismatched anchors),
attachment risk, and BEC pattern recognition.
"""
import re, os, html, base64, hashlib, math, json
from html.parser import HTMLParser
from urllib.parse import urlparse, unquote, parse_qs
from typing import Dict, Any, List, Tuple

from .common import (ROOT, registered_domain, domain_label, brand_match, SUSPICIOUS_TLDS, URL_SHORTENERS, RISKY_EXT,
                     ARCHIVE_EXT, valid_ip, FREEMAIL, LEGIT_BRAND_DOMAINS, normalize_homoglyphs)
from . import nlp_portable

# Runtime inference uses the dependency-free portable model (pure Python, any Python version).
# The scikit-learn pipeline is only needed to (re)train; it is used here only as a fallback
# when the portable export is missing and scikit-learn happens to be installed.
PORTABLE_PATH = nlp_portable.PORTABLE_PATH
MODEL_PATH = os.path.join(ROOT, "models", "phish_nlp.joblib")
META_PATH = os.path.join(ROOT, "models", "phish_nlp_meta.json")
_model = None          # nlp_portable.PortableTfidfLR  (preferred)
_sk_model = None       # sklearn Pipeline (fallback only)
_meta = {}
_feature_names = None
_load_error = None

def load_model():
    """Return the portable model (preferred) or the sklearn pipeline (fallback); None if neither is available."""
    global _model, _sk_model, _meta, _feature_names, _load_error
    if _model is not None or _sk_model is not None:
        return _model or _sk_model
    try:
        _meta = json.load(open(META_PATH, encoding="utf-8"))
    except Exception:
        _meta = {}
    try:
        _model = nlp_portable.load(PORTABLE_PATH)
        if _model is not None:
            _meta = {**_model.meta, **_meta}
            return _model
    except Exception as e:   # corrupt export -> try sklearn fallback
        _load_error = f"portable model: {e}"
    if os.path.exists(MODEL_PATH):
        try:
            import warnings, joblib
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                _sk_model = joblib.load(MODEL_PATH)
            try:
                _feature_names = _sk_model.named_steps["tfidf"].get_feature_names_out()
            except Exception:
                _feature_names = None
            return _sk_model
        except Exception as e:
            _load_error = (_load_error + "; " if _load_error else "") + f"sklearn model: {e}"
    return None

def model_status() -> Dict[str, Any]:
    m = load_model()
    return {"loaded": m is not None,
            "backend": "portable-pure-python" if _model is not None else ("scikit-learn" if _sk_model is not None else None),
            "error": _load_error, "model": _meta.get("model"), "trained_at": _meta.get("trained_at"), "accuracy": _meta.get("accuracy")}

def model_meta():
    load_model(); return _meta

def _clean(t: str) -> str:
    t = re.sub(r"https?://\S+", " URLTOKEN ", t)
    t = re.sub(r"\S+@\S+", " EMAILTOKEN ", t)
    t = re.sub(r"\d{6,}", " LONGNUM ", t)
    return re.sub(r"\s+", " ", t).strip()[:6000]

# ----------------------------------------------------------- HTML parsing --
class _HTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text: List[str] = []; self.links: List[Tuple[str, str]] = []; self.forms: List[str] = []
        self.images: List[str] = []; self.hidden_text = 0; self.scripts = 0; self.iframes = 0
        self._a_href = None; self._a_text: List[str] = []; self._skip = 0; self._style_hidden_depth = []
        self.inputs: List[str] = []; self.tracking_pixels = 0; self.meta_refresh = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        st = (a.get("style") or "").replace(" ", "").lower()
        hidden = "display:none" in st or "visibility:hidden" in st or "font-size:0" in st or "opacity:0" in st or "color:#fff" in st or "color:white" in st
        if hidden: self.hidden_text += 1
        if tag in ("script", "style"): self._skip += 1
        if tag == "script": self.scripts += 1
        if tag == "iframe": self.iframes += 1
        if tag == "a":
            self._a_href = a.get("href"); self._a_text = []
        if tag == "form": self.forms.append(a.get("action") or "")
        if tag == "input": self.inputs.append((a.get("type") or "text").lower() + ":" + (a.get("name") or ""))
        if tag == "img":
            src = a.get("src") or ""; self.images.append(src)
            w, h = a.get("width", ""), a.get("height", "")
            if (w in ("0", "1") and h in ("0", "1")) or "width:1px" in st or "height:1px" in st: self.tracking_pixels += 1
        if tag == "meta" and (a.get("http-equiv") or "").lower() == "refresh": self.meta_refresh = a.get("content")
    def handle_endtag(self, tag):
        if tag in ("script", "style"): self._skip = max(0, self._skip - 1)
        if tag == "a" and self._a_href is not None:
            self.links.append((self._a_href, " ".join(self._a_text).strip())); self._a_href = None
    def handle_data(self, data):
        if self._skip: return
        self.text.append(data)
        if self._a_href is not None: self._a_text.append(data)

def extract_body(msg) -> Dict[str, Any]:
    text_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = str(part.get("Content-Disposition") or "")
        fname = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if fname or "attachment" in disp.lower() or (ctype not in ("text/plain", "text/html") and payload):
            attachments.append({"filename": fname or f"unnamed.{ctype.split('/')[-1]}", "content_type": ctype, "size": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest(), "md5": hashlib.md5(payload).hexdigest(),
                                "_payload": payload[:4096], "inline": "inline" in disp.lower()})
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            txt = payload.decode(charset, "replace")
        except Exception:
            txt = payload.decode("utf-8", "replace")
        if ctype == "text/html": html_parts.append(txt)
        else: text_parts.append(txt)
    html_raw = "\n".join(html_parts)
    p = _HTML()
    if html_raw:
        try: p.feed(html_raw)
        except Exception: pass
    html_text = re.sub(r"[ \t]+", " ", "\n".join(p.text))
    html_text = re.sub(r"\n\s*\n+", "\n", html_text).strip()
    plain = "\n".join(text_parts).strip()
    body_text = plain if len(plain) >= len(html_text) * 0.5 and plain else html_text
    if not body_text: body_text = plain or html_text
    return {"text": body_text, "plain": plain, "html": html_raw, "html_text": html_text, "links": p.links, "forms": p.forms, "inputs": p.inputs,
            "images": p.images, "hidden_elements": p.hidden_text, "scripts": p.scripts, "iframes": p.iframes, "tracking_pixels": p.tracking_pixels,
            "meta_refresh": p.meta_refresh, "attachments": attachments}

# ------------------------------------------------------------- URL forensics
URL_RE = re.compile(r"""(?i)\b((?:https?://|hxxps?://|www\.)[^\s<>"'\)\]]+)""")

def _defang_fix(u: str) -> str:
    return u.replace("hxxp", "http").replace("[.]", ".").replace("[:]", ":")

def analyze_urls(body: Dict[str, Any], from_reg: str, org_domains: List[str]) -> Dict[str, Any]:
    urls: Dict[str, Dict[str, Any]] = {}
    def add(u: str, anchor: str = "", source: str = "body"):
        u = _defang_fix(u.strip().rstrip(".,;:!?)"))
        if u.lower().startswith("www."): u = "http://" + u
        if u.lower().startswith(("mailto:", "tel:", "javascript:", "#", "cid:", "data:")):
            if u.lower().startswith("javascript:"):
                urls.setdefault(u[:80], {"url": u[:80], "host": "", "flags": ["javascript: link"], "risk": 20, "anchor": anchor, "source": source})
            return
        key = u
        if key in urls:
            if anchor and not urls[key].get("anchor"): urls[key]["anchor"] = anchor
            return
        try: pu = urlparse(u)
        except Exception: return
        host = (pu.hostname or "").lower()
        rec = {"url": u, "host": host, "registered_domain": registered_domain(host), "scheme": pu.scheme, "path": pu.path, "anchor": anchor, "source": source, "flags": [], "risk": 0}
        def f(msg, w): rec["flags"].append(msg); rec["risk"] += w
        if not host: return
        if valid_ip(host): f("Raw IP address instead of domain", 25)
        if pu.scheme == "http": f("Unencrypted http://", 4)
        if pu.username or "@" in u.split("://", 1)[-1].split("/")[0]: f("Credentials/@ in authority — real host is after @", 30)
        if pu.port and pu.port not in (80, 443): f(f"Non-standard port {pu.port}", 10)
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS: f(f"Abuse-prone TLD .{tld}", 8)
        if rec["registered_domain"] in URL_SHORTENERS: f("URL shortener hides destination", 14)
        if host.count(".") >= 4: f("Deeply nested subdomain", 8)
        if len(host) > 40: f("Very long hostname", 5)
        if "xn--" in host: f("Punycode / IDN hostname (homograph)", 22)
        if re.search(r"%[0-9a-f]{2}", u, re.I) and len(re.findall(r"%[0-9a-f]{2}", u, re.I)) > 4: f("Heavy percent-encoding", 8)
        if re.search(r"[?&](url|redirect|redir|next|target|dest|destination|rurl|u|goto|return|continue)=https?", u, re.I) or re.search(r"[?&]\w+=https?%3a", u, re.I):
            f("Open-redirect parameter to another URL", 18)
        if re.search(r"\.(exe|scr|zip|rar|iso|js|hta|apk|msi)(\?|$)", pu.path, re.I): f("Direct download of executable/archive", 22)
        if re.search(r"(login|signin|verify|secure|account|update|confirm|password|kyc|banking|wallet|unlock|suspend|billing|invoice|reset|auth|validate)", host + pu.path, re.I):
            f("Credential/urgency keywords in URL", 6)
        if any(x in host for x in ("ngrok", "trycloudflare", "webhook.site", "000webhost", "weebly", "wixsite", "glitch.me", "repl.co", "github.io", "netlify.app", "vercel.app", "pages.dev", "web.app", "firebaseapp", "herokuapp", "azurewebsites", "blogspot", "sites.google", "forms.gle", "docs.google.com/forms", "typeform", "jotform", "formspree", "r2.dev", "workers.dev", "storage.googleapis", "s3.amazonaws", "blob.core.windows", "ipfs", "surge.sh", "godaddysites", "square.site", "mystrikingly", "yolasite")):
            f("Free hosting / form-builder / tunnel service", 12)
        bm = brand_match(host)
        if bm and bm[1] != "legit":
            f(f"Impersonates {bm[0]} ({bm[1].replace('_',' ')} of {bm[2]})", 30)
            rec["brand"] = bm[0]
        elif bm and bm[1] == "legit":
            rec["brand_legit"] = bm[0]
        for od in org_domains:
            if rec["registered_domain"] != od and domain_label(rec["registered_domain"]) and (
                    normalize_homoglyphs(domain_label(rec["registered_domain"])) == domain_label(od) or
                    (len(domain_label(od)) >= 5 and __import__("analyzer.common", fromlist=["levenshtein"]).levenshtein(domain_label(rec["registered_domain"]), domain_label(od)) <= 2)):
                f(f"Lookalike of your organisation domain {od}", 32)
        # anchor mismatch
        if anchor:
            am = URL_RE.search(anchor)
            if am:
                ah = (urlparse(_defang_fix(am.group(1) if am.group(1).startswith("http") else "http://" + am.group(1))).hostname or "").lower()
                if ah and registered_domain(ah) != rec["registered_domain"]:
                    f(f"Link text shows {ah} but points to {host}", 28)
            else:
                abm = brand_match(anchor.lower().replace(" ", ""))
                if abm and abm[1] != "legit" and rec["registered_domain"] not in LEGIT_BRAND_DOMAINS and not (bm and bm[1] == "legit"):
                    f(f"Anchor text mentions {abm[0]} but link goes to {rec['registered_domain']}", 12)
        rec["risk"] = min(100, rec["risk"])
        urls[key] = rec
    for href, anchor in body.get("links", []):
        if href: add(href, anchor, "html-anchor")
    for act in body.get("forms", []):
        if act: add(act, "", "form-action"); urls.get(_defang_fix(act.strip()), {}).setdefault("flags", []).append("HTML form posts here")
    for m in URL_RE.findall(body.get("text", "") + "\n" + body.get("plain", "")):
        add(m, "", "text")
    if body.get("meta_refresh"):
        m = re.search(r"url\s*=\s*['\"]?([^'\"\s]+)", body["meta_refresh"], re.I)
        if m: add(m.group(1), "", "meta-refresh"); 
    out = sorted(urls.values(), key=lambda r: -r["risk"])
    domains = sorted({r["registered_domain"] for r in out if r.get("registered_domain")})
    return {"urls": out[:60], "count": len(out), "domains": domains, "max_risk": max([r["risk"] for r in out], default=0),
            "distinct_domains": len(domains)}

# ---------------------------------------------------------- attachments ----
def analyze_attachments(atts: List[Dict[str, Any]]) -> Dict[str, Any]:
    out = []
    for a in atts:
        fn = (a.get("filename") or "").lower()
        exts = fn.split(".")[1:] if "." in fn else []
        ext = exts[-1] if exts else ""
        flags, risk = [], 0
        if ext in RISKY_EXT: flags.append(f"Executable/script/macro type .{ext}"); risk += 35
        if ext in ARCHIVE_EXT: flags.append("Archive — may hide executables, bypasses scanners when encrypted"); risk += 15
        if len(exts) >= 2 and exts[-2] in ("pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt") and ext in RISKY_EXT | ARCHIVE_EXT:
            flags.append(f"Double extension .{exts[-2]}.{ext} (disguised)"); risk += 25
        if re.search(r"\s{6,}\.", fn): flags.append("Whitespace padding hides real extension"); risk += 20
        if ext in ("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"):
            p = a.get("_payload", b"")
            if ext in ("doc", "xls", "ppt", "docm", "xlsm") : flags.append("Legacy Office / macro-capable format"); risk += 12
            if b"/JavaScript" in p or b"/JS" in p or b"/OpenAction" in p or b"/Launch" in p: flags.append("PDF contains JavaScript / auto-action"); risk += 30
            if re.search(rb"(invoice|payment|remittance|swift|receipt|po[ _-]?\d|statement|challan|kyc|salary)", fn.encode()): flags.append("Finance-themed lure filename"); risk += 6
        if ext in ("html", "htm", "shtml"): flags.append("HTML attachment — HTML smuggling / offline credential form"); risk += 25
        if ext == "svg": flags.append("SVG can carry embedded script"); risk += 15
        if ext in ("iso", "img", "vhd"): flags.append("Disk image — bypasses Mark-of-the-Web"); risk += 20
        if ext in ("lnk", "url"): flags.append("Shortcut file — executes commands"); risk += 30
        if ext in ("one",): flags.append("OneNote attachment — abused for malware delivery"); risk += 20
        p = a.get("_payload", b"")
        if p[:2] == b"MZ": flags.append("Payload magic bytes = Windows executable, regardless of extension"); risk += 40
        if p[:4] == b"PK\x03\x04" and ext not in ARCHIVE_EXT and ext not in ("docx", "xlsx", "pptx", "jar", "apk", "odt", "ods"): flags.append("Payload is a ZIP container with misleading extension"); risk += 20
        if a.get("size", 0) < 200 and ext in ("pdf", "docx", "xlsx"): flags.append("Suspiciously tiny document"); risk += 5
        out.append({"filename": a.get("filename"), "content_type": a.get("content_type"), "size": a.get("size"), "sha256": a.get("sha256"), "md5": a.get("md5"),
                    "extension": ext, "flags": flags, "risk": min(100, risk), "inline": a.get("inline")})
    return {"attachments": out, "count": len(out), "max_risk": max([x["risk"] for x in out], default=0)}

# ------------------------------------------------------- NLP + SE cues -----
CUES = {
    "urgency": (r"\b(urgent(ly)?|immediately|right away|within \d+ ?(hours?|hrs|minutes?|mins)|today itself|before (midnight|eod|end of (the )?day)|last (chance|warning|reminder)|final (notice|warning|reminder)|expir(e|es|ing|y) (today|soon|in)|act now|asap|time[- ]sensitive|deadline|limited time|24 ?(hours|hrs))\b", 8),
    "threat": (r"\b(suspend(ed)?|deactivat(e|ed|ion)|block(ed)?|terminat(e|ed|ion)|legal action|penalty|fine of|arrest|lawsuit|permanently (closed|disabled|deleted)|lose access|unauthori[sz]ed (access|login|transaction)|unusual (activity|sign[- ]?in)|security (alert|breach|warning)|account (is|has been|will be) (locked|limited|restricted|compromised))\b", 9),
    "credential": (r"\b(verify|validate|confirm|update|re-?enter|reset)\b.{0,40}\b(password|passcode|credentials?|login|account|identity|kyc|pan|aadhaa?r|otp|pin|cvv|card (number|details)|net ?banking|upi)\b", 12),
    "financial": (r"\b(wire transfer|bank transfer|rtgs|neft|imps|upi|remit(tance)?|beneficiary|swift code|ifsc|account number|invoice|payment (is )?(due|pending|overdue)|outstanding (amount|payment|dues)|refund|reimbursement|tax refund|gift ?cards?|bitcoin|btc|crypto|wallet address|itunes|google play card|amazon (gift )?card|processing fee|registration fee|advance fee|lottery|prize|won|winner|inheritance|claim (your|the) (money|fund|amount))\b", 8),
    "authority": (r"\b(rbi|reserve bank|income tax|it department|cbi|police|cyber ?crime|court|ministry|government of india|govt\.?|sebi|npci|uidai|trai|customs|ed |enforcement directorate|high court|supreme court|cert-in|aicte|ugc|nta|hr department|it (help)?desk|system administrator|mail administrator)\b", 6),
    "secrecy": (r"\b(keep (this|it) (confidential|private|between us|secret)|do not (tell|share|disclose|discuss)|don'?t (tell|share|mention)|confidential(ly)?|discreet(ly)?|not to be shared|strictly private)\b", 10),
    "availability": (r"\b(in a (meeting|conference)|can'?t talk|cannot talk|unable to (talk|call)|on a call|travel+ing|out of (office|station|the country)|busy right now|reply (by|via|on) (email|whatsapp|text)|text me|whatsapp me|share your (mobile|phone|whatsapp) number|are you (at your desk|available|free))\b", 10),
    "reward": (r"\b(congratulations?|you (have )?(been )?(selected|won|shortlisted|chosen)|lucky (draw|winner)|cash ?back|bonus|reward points|exclusive offer|free (gift|iphone|recharge|voucher))\b", 6),
    "generic_greeting": (r"^\s*(dear|hello|hi|attention)\s+(customer|user|member|account holder|sir/madam|sir or madam|valued|beneficiary|employee|student|applicant|client|friend)\b", 5),
    "click_lure": (r"\b(click (here|below|the link|on the link|this link)|tap (here|below)|follow the link|use the (link|button) below|open the attachment|see attached|download (the )?(attached|attachment|file))\b", 5),
    "password_reset": (r"\b(password (will )?expire|expir(ing|ed) password|mailbox (is )?(almost )?full|storage (limit|quota)|quota exceeded|upgrade (your )?mailbox|re-?activate (your )?(mailbox|email)|email verification required)\b", 10),
    "delivery": (r"\b(parcel|package|shipment|consignment|courier|delivery (attempt|failed|fee|charges)|customs (fee|duty|clearance)|could not be delivered|redeliver)\b", 6),
    "poor_language": (r"\b(kindly do the needful|revert back|do the needful|please to|your account have|has been (send|sended)|informations|the same is|you are hereby|as per (our|the) (record|records|policy) your)\b", 3),
}

BEC_PATTERNS = {
    "Payment diversion / invoice fraud": r"\b((new|updated|changed|different) (bank )?(account|banking|payment|beneficiary) (details|information|number)|bank (details|account) (has|have) (been )?(changed|updated)|remit (the )?(payment|amount) to|update (the|our) (bank|beneficiary|payment) (details|information)|revised invoice|pending (invoice|payment) of)\b",
    "Executive impersonation / CEO fraud": r"\b(this is (the )?(director|principal|vc|vice chancellor|registrar|chairman|ceo|cfo|dean|md|hod)|sent from my (iphone|ipad|android|mobile|samsung)|are you (at your desk|available|in office)|i need (you to|a favou?r)|quick (task|favou?r|request)|handle (this|something) (for me|urgently|discreetly))\b",
    "Gift card scam": r"\b(gift ?cards?|itunes cards?|google play (gift )?cards?|amazon (gift )?cards?|steam cards?|scratch (the )?(card|code)|send (me )?the (codes?|card numbers?|pictures? of the cards?))\b",
    "Payroll / salary diversion": r"\b(change (my|the) (direct deposit|salary account|payroll (account|details))|update (my )?bank (account )?for (salary|payroll)|salary (credit|account) (change|update))\b",
    "Credential harvesting": r"\b(verify|validate|confirm|re-?activate|unlock|update|login to|sign in to)\b.{0,60}\b(account|mailbox|email|password|credentials|kyc|identity|portal|office ?365|microsoft ?365|google (account|workspace)|sharepoint|onedrive)\b",
    "Vendor / supplier impersonation": r"\b(purchase order|po (no|number)|quotation|proforma invoice|delivery challan|gst invoice|tax invoice|payment advice|remittance advice|outstanding dues|overdue invoice|statement of account)\b",
    "Sextortion / blackmail": r"\b(webcam|recorded you|your (browsing|search) history|adult (sites?|content|videos?)|send (it|the video) to (all )?your contacts|bitcoin (wallet|address)|i have (hacked|full access to) your (device|computer|phone|account))\b",
    "Job / scholarship / loan scam": r"\b(work[- ]from[- ]home|part[- ]time job|earn (rs\.?|₹|\$) ?\d|registration fee|processing fee|security deposit|loan (approved|pre-?approved|sanctioned)|scholarship (disbursement|amount|is on hold|approved)|offer letter attached)\b",
    "Government / tax impersonation": r"\b(income tax refund|tax refund of|it refund|pan (card )?(update|verification|inactive|deactivated)|aadhaa?r (link|update|suspended|verification)|e-?challan|traffic (fine|challan)|electricity (bill|connection|disconnected)|gas connection|subsidy|pm ?kisan|e-?shram)\b",
}

NEGATION = re.compile(r"(?:\bno\b|\bnot\b|\bwithout\b|\bnever\b|\bfree of\b|\bisn't\b|\bwon't\b|\bdo not\b|\bdon't\b)\W+(?:\w+\W+){0,2}$")

def _negated(tl: str, start: int) -> bool:
    return bool(NEGATION.search(tl[max(0, start - 30):start]))

def text_features(text: str, subject: str) -> Dict[str, Any]:
    t = (subject + "\n" + text)
    tl = t.lower()
    cues = {}
    score = 0
    for name, (pat, w) in CUES.items():
        ms = [m.group(0) for m in re.finditer(pat, tl, re.I | re.M) if not _negated(tl, m.start())]
        if ms:
            uniq = []
            for m in ms:
                if m not in uniq: uniq.append(m)
            cues[name] = {"matches": uniq[:6], "count": len(ms), "weight": w}
            score += w * min(3, len(uniq)) ** 0.5
    bec = {}
    for name, pat in BEC_PATTERNS.items():
        ms = [m.group(0) for m in re.finditer(pat, tl, re.I) if not _negated(tl, m.start())]
        if ms:
            uniq = []
            for m in ms:
                if m not in uniq: uniq.append(m)
            bec[name] = uniq[:5]
    caps_words = re.findall(r"\b[A-Z]{4,}\b", t)
    excl = t.count("!")
    money = re.findall(r"(?:rs\.?|inr|₹|\$|usd|eur|£)\s?\d[\d,]*(?:\.\d+)?|\d[\d,]*\s?(?:rupees|lakhs?|crores?|dollars?)", tl)
    phones = re.findall(r"(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b|\+\d{1,3}[\s-]?\d{6,12}", t)
    crypto = re.findall(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b|\b0x[a-fA-F0-9]{40}\b", t)
    upi = re.findall(r"\b[\w.\-]{3,}@(?:ybl|paytm|okaxis|oksbi|okhdfcbank|okicici|upi|apl|ibl|axl|fbl|jio|airtel)\b", tl)
    return {"cues": cues, "cue_score": min(100, round(score)), "bec_patterns": bec, "caps_words": len(caps_words), "exclamations": excl,
            "money_mentions": money[:6], "phone_numbers": list(dict.fromkeys(phones))[:5], "crypto_wallets": crypto[:3], "upi_ids": upi[:5],
            "length": len(text), "word_count": len(text.split())}

def nlp_classify(text: str, subject: str) -> Dict[str, Any]:
    m = load_model()
    doc = _clean(subject + " " + text)
    if m is None or len(doc.split()) < 3:
        return {"available": m is not None, "phishing_probability": None, "top_terms": [], "legit_terms": [],
                "note": "insufficient text" if m is not None else ("model not available: " + (_load_error or "not trained"))}
    if _model is not None:   # portable pure-Python inference (default path)
        p, pos, neg = _model.explain(doc, 10, 6)
        top_phish = [{"term": t, "weight": round(w, 3)} for t, w in pos]
        top_legit = [{"term": t, "weight": round(w, 3)} for t, w in neg]
    else:                    # scikit-learn fallback
        p = float(m.predict_proba([doc])[0, 1])
        try:
            vec, clf = m.named_steps["tfidf"], m.named_steps["clf"]
            X = vec.transform([doc])
            coef = clf.coef_[0]
            idx = X.nonzero()[1]
            names = _feature_names if _feature_names is not None else vec.get_feature_names_out()
            Xd = X.toarray()[0]
            contrib = [(str(names[i]), float(Xd[i] * coef[i])) for i in idx]
            contrib.sort(key=lambda x: -abs(x[1]))
            top_phish = [{"term": t, "weight": round(w, 3)} for t, w in contrib if w > 0][:10]
            top_legit = [{"term": t, "weight": round(w, 3)} for t, w in contrib if w < 0][:6]
        except Exception:
            top_phish, top_legit = [], []
    return {"available": True, "phishing_probability": round(float(p), 4), "top_terms": top_phish, "legit_terms": top_legit,
            "model": _meta.get("model", "tfidf+lr")}

def analyze_content(msg, subject: str, from_reg: str, org_domains: List[str], vips: List[str]) -> Dict[str, Any]:
    body = extract_body(msg)
    urls = analyze_urls(body, from_reg, org_domains)
    atts = analyze_attachments(body["attachments"])
    feats = text_features(body["text"], subject)
    nlp = nlp_classify(body["text"], subject)
    findings = []
    def flag(sev, code, title, detail, weight):
        findings.append({"severity": sev, "code": code, "title": title, "detail": detail, "weight": weight})
    # VIP impersonation by display name (passed in by caller through vips list of names)
    html_flags = []
    if body["hidden_elements"]: html_flags.append(f"{body['hidden_elements']} hidden element(s) (display:none / zero font) — filter-evasion text")
    if body["scripts"]: html_flags.append(f"{body['scripts']} <script> block(s) in email HTML")
    if body["iframes"]: html_flags.append(f"{body['iframes']} <iframe>")
    if body["forms"]: html_flags.append("HTML <form> inside the email — direct credential capture")
    if body["tracking_pixels"]: html_flags.append(f"{body['tracking_pixels']} tracking pixel(s)")
    if body["meta_refresh"]: html_flags.append("meta-refresh auto redirect")
    if any(i.startswith("password") for i in body["inputs"]): html_flags.append("Password input field inside email")
    if body["html"] and len(body["html_text"].strip()) < 40 and body["images"]: html_flags.append("Image-only email (text hidden in image to evade filters)")
    for h in html_flags:
        sev = "high" if ("form" in h.lower() or "password" in h.lower() or "script" in h.lower()) else "medium" if "hidden" in h.lower() or "image-only" in h.lower() else "low"
        flag(sev, "C-HTML", "HTML construction anomaly", h, {"high": 14, "medium": 8, "low": 2}[sev])
    # url findings
    for u in urls["urls"][:8]:
        if u["risk"] >= 25:
            flag("critical" if u["risk"] >= 50 else "high", "C-URL", f"Malicious-looking link: {u['host'][:60]}", "; ".join(u["flags"][:4]), min(30, u["risk"] // 2))
        elif u["risk"] >= 12:
            flag("medium", "C-URL", f"Suspicious link: {u['host'][:60]}", "; ".join(u["flags"][:3]), u["risk"] // 3)
    if urls["distinct_domains"] >= 6:
        flag("low", "C-URL-MANY", "Many distinct link domains", f"{urls['distinct_domains']} domains in one message", 3)
    for a in atts["attachments"]:
        if a["risk"] >= 30:
            flag("critical" if a["risk"] >= 50 else "high", "C-ATT", f"Dangerous attachment: {a['filename']}", "; ".join(a["flags"][:3]), min(30, a["risk"] // 2))
        elif a["risk"] >= 10:
            flag("medium", "C-ATT", f"Attachment needs sandboxing: {a['filename']}", "; ".join(a["flags"][:3]), a["risk"] // 3)
    for name, c in feats["cues"].items():
        pretty = {"urgency": "Urgency pressure", "threat": "Threat / fear language", "credential": "Credential request", "financial": "Financial lure / payment request",
                  "authority": "Authority invocation", "secrecy": "Secrecy request", "availability": "'Unavailable, reply by text' pretext", "reward": "Reward / prize lure",
                  "generic_greeting": "Generic greeting", "click_lure": "Click / open lure", "password_reset": "Mailbox / password expiry pretext", "delivery": "Parcel / delivery pretext", "poor_language": "Non-native phrasing"}[name]
        sev = "high" if name in ("credential", "secrecy", "availability", "password_reset") else "medium" if name in ("threat", "urgency", "financial") else "low"
        flag(sev, f"C-NLP-{name.upper()}", pretty, "e.g. " + " | ".join(f'"{m}"' for m in c["matches"][:3]), min(15, c["weight"] * min(2, c["count"]) // 1))
    for name, ms in feats["bec_patterns"].items():
        flag("high", "C-BEC", f"BEC pattern: {name}", "e.g. " + " | ".join(f'"{m}"' for m in ms[:3]), 14)
    if feats["crypto_wallets"]: flag("high", "C-CRYPTO", "Cryptocurrency wallet address in body", ", ".join(feats["crypto_wallets"]), 15)
    if feats["upi_ids"]: flag("medium", "C-UPI", "UPI ID in body", ", ".join(feats["upi_ids"]), 8)
    if nlp.get("phishing_probability") is not None:
        p = nlp["phishing_probability"]
        if p >= 0.85: flag("high", "C-ML", f"ML classifier: {p*100:.0f}% phishing", "Top contributing terms: " + ", ".join(t["term"] for t in nlp["top_terms"][:6]), 22)
        elif p >= 0.6: flag("medium", "C-ML", f"ML classifier: {p*100:.0f}% phishing", "Top terms: " + ", ".join(t["term"] for t in nlp["top_terms"][:6]), 12)
        elif p <= 0.2: flag("info", "C-ML", f"ML classifier: {p*100:.0f}% phishing (looks benign)", "", 0)
    body_out = {k: v for k, v in body.items() if k not in ("attachments", "html")}
    body_out["attachments"] = atts["attachments"]
    body_out["html_length"] = len(body["html"])
    body_out["text_preview"] = body["text"][:3000]
    del body_out["text"]; del body_out["plain"]; del body_out["html_text"]
    return {"body": body_out, "urls": urls, "attachments": atts, "features": feats, "nlp": nlp, "findings": findings}
