"""Shared constants, brand directory, helpers."""
import re, os, json, ipaddress
import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))      # backend/  (installation dir, may be read-only)
CONFIG_DIR = os.path.join(ROOT, "config")                                # bundled default org profile
ASSET_DIR = os.path.join(ROOT, "data")                                   # bundled read-only seeds (geo_seed, tor list)
# Writable location for everything the app creates (SQLite store, sealed evidence, intel cache, settings).
# The desktop app points MAILTRACE_HOME at the per-user AppData folder; the web launcher keeps backend/data.
DATA_DIR = os.environ.get("MAILTRACE_HOME") or ASSET_DIR
os.makedirs(DATA_DIR, exist_ok=True)
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
ORG_OVERRIDE_PATH = os.path.join(DATA_DIR, "org_profile.json")

DEFAULT_SETTINGS = {"offline": False, "analyst": "analyst@aicte-cybercell", "retention_days": 180}

def load_settings() -> dict:
    s = dict(DEFAULT_SETTINGS)
    try:
        if os.path.exists(SETTINGS_PATH):
            s.update(json.load(open(SETTINGS_PATH, encoding="utf-8")))
    except Exception:
        pass
    return s

def save_settings(s: dict) -> dict:
    cur = load_settings(); cur.update({k: v for k, v in s.items() if k in DEFAULT_SETTINGS})
    json.dump(cur, open(SETTINGS_PATH, "w", encoding="utf-8"), indent=2)
    return cur

def load_org_profile():
    for p in (ORG_OVERRIDE_PATH, os.path.join(CONFIG_DIR, "org_profile.json")):
        if os.path.exists(p):
            try:
                return json.load(open(p, encoding="utf-8"))
            except Exception:
                continue
    return {"organization": "Unconfigured", "domains": [], "vips": [], "partners": [], "esp": ""}

def save_org_profile(profile: dict) -> dict:
    base = load_org_profile(); base.update(profile)
    json.dump(base, open(ORG_OVERRIDE_PATH, "w", encoding="utf-8"), indent=2)
    return base

def registered_domain(host: str) -> str:
    if not host:
        return ""
    host = host.strip().lower().strip("[]<>")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    ext = _EXTRACT(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host

def domain_label(host: str) -> str:
    ext = _EXTRACT(host or "")
    return ext.domain or ""

def is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or a.is_unspecified
    except ValueError:
        return True

def valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip); return True
    except ValueError:
        return False

# --- Brand directory: brand -> (keywords, legit registered domains) ---------
BRANDS = {
    "State Bank of India": (["sbi", "onlinesbi", "statebank", "yono"], ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi", "sbicard.com"]),
    "ICICI Bank": (["icici"], ["icicibank.com", "icicidirect.com", "iciciprulife.com"]),
    "HDFC Bank": (["hdfc"], ["hdfcbank.com", "hdfc.com", "hdfclife.com"]),
    "Axis Bank": (["axisbank"], ["axisbank.com"]),
    "Punjab National Bank": (["pnb"], ["pnbindia.in"]),
    "Kotak Mahindra Bank": (["kotak"], ["kotak.com"]),
    "Paytm": (["paytm"], ["paytm.com", "paytmbank.com"]),
    "PhonePe": (["phonepe"], ["phonepe.com"]),
    "Income Tax Department": (["incometax", "incometaxindia", "itdept"], ["incometax.gov.in", "incometaxindia.gov.in", "incometaxindiaefiling.gov.in"]),
    "UIDAI / Aadhaar": (["uidai", "aadhaar", "aadhar"], ["uidai.gov.in"]),
    "EPFO": (["epfo", "epfindia"], ["epfindia.gov.in"]),
    "IRCTC": (["irctc"], ["irctc.co.in"]),
    "AICTE": (["aicte"], ["aicte-india.org"]),
    "UGC": (["ugc"], ["ugc.gov.in", "ugc.ac.in"]),
    "NTA": (["nta"], ["nta.ac.in", "nta.nic.in"]),
    "Reserve Bank of India": (["rbi"], ["rbi.org.in"]),
    "NPCI / UPI": (["npci", "bhimupi"], ["npci.org.in"]),
    "LIC": (["licindia"], ["licindia.in"]),
    "Microsoft": (["microsoft", "office365", "outlook", "microsoftonline", "sharepoint", "onedrive"], ["microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com", "sharepoint.com", "onedrive.com", "hotmail.com", "microsoftonline-p.com", "microsoft.net"]),
    "Google": (["google", "gmail", "googledocs"], ["google.com", "gmail.com", "googlemail.com", "google.co.in", "googleapis.com", "goog"]),
    "Apple": (["apple", "icloud", "appleid"], ["apple.com", "icloud.com"]),
    "Amazon": (["amazon", "amzn"], ["amazon.in", "amazon.com", "amazonaws.com", "amazonses.com", "amazon.co.uk"]),
    "PayPal": (["paypal"], ["paypal.com"]),
    "Netflix": (["netflix"], ["netflix.com"]),
    "Meta / Facebook": (["facebook", "instagram", "whatsapp", "meta"], ["facebook.com", "fb.com", "instagram.com", "whatsapp.com", "meta.com", "facebookmail.com"]),
    "LinkedIn": (["linkedin"], ["linkedin.com"]),
    "DHL": (["dhl"], ["dhl.com", "dhl.in"]),
    "FedEx": (["fedex"], ["fedex.com"]),
    "Blue Dart": (["bluedart"], ["bluedart.com"]),
    "India Post": (["indiapost"], ["indiapost.gov.in"]),
    "Airtel": (["airtel"], ["airtel.in", "airtel.com"]),
    "Jio": (["jio", "reliancejio"], ["jio.com", "ril.com"]),
    "Dropbox": (["dropbox"], ["dropbox.com", "dropboxmail.com"]),
    "DocuSign": (["docusign"], ["docusign.com", "docusign.net"]),
    "Adobe": (["adobe"], ["adobe.com"]),
    "Zoom": (["zoom"], ["zoom.us", "zoom.com"]),
    "Flipkart": (["flipkart"], ["flipkart.com"]),
    "DigiLocker": (["digilocker"], ["digilocker.gov.in"]),
    "NIC / GoI": (["nic", "gov"], ["nic.in", "gov.in"]),
}
LEGIT_BRAND_DOMAINS = {d for _, (_, ds) in BRANDS.items() for d in ds}

FREEMAIL = {"gmail.com", "yahoo.com", "yahoo.in", "yahoo.co.in", "outlook.com", "hotmail.com", "live.com", "rediffmail.com",
            "protonmail.com", "proton.me", "aol.com", "icloud.com", "mail.com", "yandex.com", "yandex.ru", "zoho.com", "gmx.com",
            "gmx.de", "tutanota.com", "mail.ru", "inbox.lv", "163.com", "qq.com", "ymail.com"}

# hostnames / domains of well-known ESPs & mail providers whose Received hops are considered trustworthy once entered
ESP_DOMAINS = {
    "google": ["google.com", "googlemail.com", "gmail.com", "1e100.net"],
    "microsoft": ["outlook.com", "protection.outlook.com", "microsoft.com", "hotmail.com", "office365.com", "exchangelabs.com"],
    "amazon_ses": ["amazonses.com", "amazonaws.com"],
    "sendgrid": ["sendgrid.net"],
    "mailgun": ["mailgun.org", "mailgun.net"],
    "zoho": ["zoho.com", "zoho.in", "zohomail.com", "zoho.eu"],
    "mailchimp": ["mcsv.net", "mcdlv.net", "rsgsv.net", "mailchimp.com"],
    "proofpoint": ["pphosted.com", "proofpoint.com"],
    "mimecast": ["mimecast.com"],
    "nic": ["nic.in", "mgovcloud.in", "gov.in"],
    "yahoo": ["yahoo.com", "yahoodns.net"],
    "rediff": ["rediffmail.com", "rediff.com"],
}
ESP_ALL = {d for v in ESP_DOMAINS.values() for d in v}

def esp_for_host(host: str):
    host = (host or "").lower().rstrip(".")
    for name, doms in ESP_DOMAINS.items():
        for d in doms:
            if host == d or host.endswith("." + d):
                return name
    return None

SUSPICIOUS_TLDS = {"top", "xyz", "tk", "ml", "ga", "cf", "gq", "buzz", "icu", "click", "link", "zip", "mov", "cam", "rest", "monster",
                   "quest", "cyou", "cfd", "sbs", "bond", "surf", "work", "info", "biz", "pw", "cc", "su", "ru", "vip", "site", "online",
                   "website", "space", "fun", "live", "store", "shop", "tech", "club", "one", "lol", "pro"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
                  "rebrand.ly", "bl.ink", "t.ly", "lnkd.in", "s.id", "surl.li", "clck.ru", "v.gd", "qrco.de"}
RISKY_EXT = {"exe", "scr", "pif", "com", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "msi", "msp", "hta", "cpl", "jar",
             "lnk", "iso", "img", "vhd", "docm", "xlsm", "pptm", "dotm", "xlam", "html", "htm", "shtml", "svg", "one", "chm", "reg", "apk"}
ARCHIVE_EXT = {"zip", "rar", "7z", "tar", "gz", "arj", "cab", "ace"}

def levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    if not a: return len(b)
    if not b: return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s", "|": "l",
                            "ı": "i", "і": "i", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x"})

def normalize_homoglyphs(s: str) -> str:
    s = (s or "").lower().translate(HOMOGLYPHS)
    return s.replace("rn", "m").replace("vv", "w").replace("cl", "d")

def brand_match(host: str):
    """Return (brand, kind, detail) if host impersonates a brand, kind in {legit, keyword, lookalike, subdomain_abuse}."""
    host = (host or "").lower().rstrip(".")
    if not host:
        return None
    reg = registered_domain(host)
    label = domain_label(host)
    if reg in LEGIT_BRAND_DOMAINS:
        for brand, (_, doms) in BRANDS.items():
            if reg in doms:
                return (brand, "legit", reg)
    # brand's legit domain embedded as sub-label:  login.microsoftonline.com.evil.xyz
    for brand, (_, doms) in BRANDS.items():
        for d in doms:
            if len(d) > 6 and (host.startswith(d + ".") or ("." + d + ".") in host) and reg != d:
                return (brand, "subdomain_abuse", d)
    labels = host.replace("-", ".").split(".")
    norm_label = normalize_homoglyphs(label)
    for brand, (kws, doms) in BRANDS.items():
        for kw in kws:
            if len(kw) < 4:
                if kw in labels:          # short keywords must be a full label (sbi, pnb, nta, ugc ...)
                    return (brand, "keyword", kw)
                continue
            if kw in host.replace("-", "").replace(".", ""):
                return (brand, "keyword", kw)
        for d in doms:
            dl = domain_label(d)
            if len(dl) >= 5 and label != dl:
                if levenshtein(label, dl) <= (1 if len(dl) < 7 else 2) or (norm_label == dl and label != dl):
                    return (brand, "lookalike", d)
    return None

IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
IPV6_RE = re.compile(r"(?i)(?<![:\w.])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![:\w])")

def find_ips(text: str):
    out = []
    for m in IPV4_RE.findall(text or ""):
        if m not in out: out.append(m)
    for m in IPV6_RE.findall(text or ""):
        m = m.strip(":") if m.count("::") == 0 and (m.startswith(":") or m.endswith(":")) else m
        if m.count(":") >= 2 and valid_ip(m) and m not in out and not m.lower().startswith("::"):
            out.append(m)
    return out
