"""
Intelligence enrichment layer with graceful offline fallback.

  DNS      : SPF / DMARC / MX / A / PTR  (dnspython, 4s timeout)
  SPF eval : own lightweight evaluator (ip4/ip6/a/mx/include/redirect/all, recursion-limited)
  GeoIP    : ip-api.com batch endpoint (free, no key, 45 req/min) -> cached; bundled seed table for offline
  Tor      : bundled exit-node snapshot (data/tor_exits.txt), refreshed opportunistically
  RDAP     : rdap.org bootstrap for domain registration (age/registrar/NS) and IP netblock (abuse contact)
  ASN class: hosting / VPN / proxy / residential / government heuristics
"""
import os, re, json, time, ipaddress, threading
from typing import Dict, Any, List, Optional
from .common import DATA_DIR, ASSET_DIR, is_private_ip, valid_ip, registered_domain, load_settings

try:
    import dns.resolver, dns.reversename
    _RES = dns.resolver.Resolver(); _RES.lifetime = 4.0; _RES.timeout = 2.0
    DNS_OK = True
except Exception:
    DNS_OK = False

try:
    import httpx
    HTTP_OK = True
except Exception:
    HTTP_OK = False

OFFLINE = os.environ.get("MAILTRACE_OFFLINE", "0") == "1" or bool(load_settings().get("offline"))
CACHE_PATH = os.path.join(DATA_DIR, "intel_cache.json")
_lock = threading.Lock()
_cache: Dict[str, Any] = {}
if os.path.exists(CACHE_PATH):
    try:
        _cache = json.load(open(CACHE_PATH, encoding="utf-8"))
    except Exception:
        _cache = {}

def _cget(k, ttl=86400 * 3):
    v = _cache.get(k)
    if not v:
        return None
    if v.get("_tr"):                       # transient (rate-limited / server error) → retry after 2 minutes
        ttl = min(ttl, 120)
    if time.time() - v.get("_t", 0) < ttl:
        return v["v"]
    return None

_dirty = 0
def _cset(k, v, transient: bool = False):
    global _dirty
    with _lock:
        _cache[k] = {"_t": time.time(), "v": v, **({"_tr": True} if transient else {})}
        _dirty += 1
        if _dirty >= 25:                   # batched persistence (bulk ingestion may add thousands of entries)
            _dirty = 0
            try:
                json.dump(_cache, open(CACHE_PATH, "w", encoding="utf-8"))
            except Exception:
                pass

def flush_cache():
    try:
        json.dump(_cache, open(CACHE_PATH, "w", encoding="utf-8"))
    except Exception:
        pass

# ------------------------------------------------------------------- DNS ---
def _txt(name: str) -> List[str]:
    if OFFLINE or not DNS_OK:
        return []
    ck = f"txt:{name}"
    c = _cget(ck)
    if c is not None:
        return c
    out = []
    try:
        for r in _RES.resolve(name, "TXT"):
            out.append(b"".join(r.strings).decode("utf-8", "ignore"))
    except Exception:
        out = []
    _cset(ck, out)
    return out

def _a(name: str) -> List[str]:
    if OFFLINE or not DNS_OK:
        return []
    ck = f"a:{name}"
    c = _cget(ck)
    if c is not None:
        return c
    out = []
    for rt in ("A", "AAAA"):
        try:
            out += [r.to_text() for r in _RES.resolve(name, rt)]
        except Exception:
            pass
    _cset(ck, out)
    return out

def get_mx(domain: str) -> List[str]:
    if OFFLINE or not DNS_OK or not domain:
        return []
    ck = f"mx:{domain}"
    c = _cget(ck)
    if c is not None:
        return c
    out = []
    try:
        out = sorted([(r.preference, r.exchange.to_text().rstrip(".")) for r in _RES.resolve(domain, "MX")])
        out = [x[1] for x in out]
    except Exception:
        out = []
    _cset(ck, out)
    return out

def get_ptr(ip: str) -> Optional[str]:
    if OFFLINE or not DNS_OK or not valid_ip(ip):
        return None
    ck = f"ptr:{ip}"
    c = _cget(ck)
    if c is not None:
        return c or None
    try:
        name = dns.reversename.from_address(ip)
        v = _RES.resolve(name, "PTR")[0].to_text().rstrip(".")
    except Exception:
        v = ""
    _cset(ck, v)
    return v or None

def get_spf_record(domain: str) -> Optional[str]:
    for t in _txt(domain):
        if t.lower().startswith("v=spf1"):
            return t
    return None

def get_dmarc(domain: str) -> Dict[str, Any]:
    rec = None
    for t in _txt(f"_dmarc.{domain}"):
        if t.lower().startswith("v=dmarc1"):
            rec = t; break
    pol = None
    if rec:
        m = re.search(r"\bp\s*=\s*(\w+)", rec, re.I)
        pol = m.group(1).lower() if m else None
    return {"record": rec, "policy": pol}

def _ip_in(ip: str, cidr: str) -> bool:
    try:
        if "/" not in cidr:
            return ipaddress.ip_address(ip) == ipaddress.ip_address(cidr)
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False

def check_spf(ip: str, domain: str, depth: int = 0, lookups: List[int] = None) -> Dict[str, Any]:
    """Minimal RFC 7208 evaluator. Returns result in pass/fail/softfail/neutral/none/permerror."""
    if lookups is None:
        lookups = [0]
    if OFFLINE or not DNS_OK:
        return {"result": "none", "detail": "offline: SPF not evaluated", "record": None}
    if depth > 8 or lookups[0] > 12:
        return {"result": "permerror", "detail": "too many DNS lookups / include depth", "record": None}
    rec = get_spf_record(domain)
    if not rec:
        return {"result": "none", "detail": f"no SPF record for {domain}", "record": None}
    terms = rec.split()[1:]
    for term in terms:
        q = "+"
        t = term
        if t[0] in "+-~?":
            q, t = t[0], t[1:]
        tl = t.lower()
        matched = False
        if tl == "all":
            matched = True
        elif tl.startswith("ip4:") or tl.startswith("ip6:"):
            matched = _ip_in(ip, t[4:])
        elif tl.startswith("include:"):
            lookups[0] += 1
            sub = check_spf(ip, t[8:], depth + 1, lookups)
            if sub["result"] == "pass":
                matched = True
        elif tl.startswith("redirect="):
            lookups[0] += 1
            sub = check_spf(ip, t[9:], depth + 1, lookups)
            sub["record"] = rec
            return sub
        elif tl == "a" or tl.startswith("a:") or tl.startswith("a/"):
            lookups[0] += 1
            host = t[2:].split("/")[0] if ":" in t else domain
            matched = ip in _a(host)
        elif tl == "mx" or tl.startswith("mx:"):
            lookups[0] += 1
            host = t[3:] if ":" in t else domain
            for mx in get_mx(host)[:5]:
                if ip in _a(mx):
                    matched = True; break
        elif tl.startswith("exists:") or tl.startswith("ptr"):
            continue
        if matched:
            res = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[q]
            return {"result": res, "detail": f"matched '{term}' in SPF of {domain}", "record": rec}
    return {"result": "neutral", "detail": f"no mechanism matched in {domain}", "record": rec}

# ----------------------------------------------------------------- GeoIP ---
_TOR: set = set()
for _p in (os.path.join(DATA_DIR, "tor_exits.txt"), os.path.join(ASSET_DIR, "tor_exits.txt")):
    try:
        _TOR = set(open(_p, encoding="utf-8", errors="ignore").read().split())
        if _TOR: break
    except Exception:
        continue

def refresh_tor():
    global _TOR
    if OFFLINE or not HTTP_OK:
        return
    try:
        r = httpx.get("https://check.torproject.org/torbulkexitlist", timeout=8)
        if r.status_code == 200 and len(r.text) > 1000:
            _TOR = set(r.text.split())
            open(os.path.join(DATA_DIR, "tor_exits.txt"), "w", encoding="utf-8").write(r.text)
    except Exception:
        pass

_SEED: Dict[str, Any] = {}
try:
    _SEED = json.load(open(os.path.join(ASSET_DIR, "geo_seed.json"), encoding="utf-8"))
except Exception:
    _SEED = {}

VPN_HINTS = ("vpn", "nord", "express", "proton", "mullvad", "surfshark", "private internet", "m247", "datacamp", "cdn77", "packethub", "ipxo", "hydra", "windscribe", "cyberghost", "tunnel", "anonym", "privacy", "hide", "purevpn", "zenlayer")
HOSTING_HINTS = ("hosting", "cloud", "server", "vps", "datacenter", "data center", "digitalocean", "linode", "akamai", "hetzner", "ovh", "contabo", "vultr", "amazon", "aws", "google", "microsoft", "azure", "alibaba", "oracle", "leaseweb", "choopa", "hostpapa", "hostinger", "godaddy", "namecheap", "fastly", "cloudflare", "colocation", "colo", "dedicated", "scaleway", "upcloud", "kamatera", "psychz", "quadranet", "colocrossing", "buyvm", "frantech", "hostwinds", "ionos", "1&1", "strato", "shinjiru", "hostafrica", "layer7", "fasthost", "krez", "media land", "cloud.ru", "stiftung", "foundation")
MOBILE_HINTS = ("mobile", "cellular", "wireless", "jio", "airtel", "vodafone", "idea", "mtn", "telkom", "orange", "telenor", "bharti", "safaricom", "glo", "9mobile", "telkomsel", "vi ", "bsnl", "mtnl")
GOV_HINTS = ("national informatics", "nic", "government", "govt", "ministry", "ernet", "nkn", "defence", "nicnet")
BULLETPROOF_HINTS = ("media land", "krez", "fasthost.ltd", "ufo technologies", "layer7", "hostslim", "flokinet", "eurobyte", "alexhost", "cloudzy", "chang way", "selectel", "prospero", "aeza", "stark industries", "virtualine", "4vendeta", "cyberdyne")

def _has(isp: str, hints) -> bool:
    for h in hints:
        if len(h) <= 4:
            if re.search(rf"(?<![a-z0-9]){re.escape(h.strip())}(?![a-z0-9])", isp):
                return True
        elif h in isp:
            return True
    return False

ESP_ISP_HINTS = ("google llc", "google public", "microsoft corporation", "amazon.com", "amazon technologies", "amazon data services", "sendgrid", "twilio", "mailgun", "mailchimp", "the rocket science group", "zoho", "yahoo", "oath holdings", "proofpoint", "mimecast", "rackspace", "outlook", "office 365", "salesforce", "sparkpost", "message systems", "constant contact", "mandrill", "postmark", "brevo", "sendinblue", "netcore", "pepipost")

def classify_ip(g: Dict[str, Any]) -> Dict[str, Any]:
    isp = f"{g.get('isp','')} {g.get('org','')} {g.get('as','')} {g.get('asname','')}".lower()
    rdns = (g.get("reverse") or "").lower()
    tags = []
    ip = g.get("query") or g.get("ip")
    from .common import esp_for_host
    if esp_for_host(rdns) or _has(isp, ESP_ISP_HINTS):
        tags.append("EMAIL_PROVIDER")
    if ip in _TOR:
        tags.append("TOR_EXIT")
    if g.get("proxy") and "EMAIL_PROVIDER" not in tags:
        tags.append("PROXY/VPN")
    elif _has(isp, VPN_HINTS) and "EMAIL_PROVIDER" not in tags:
        tags.append("VPN_PROVIDER")
    if (g.get("hosting") or _has(isp, HOSTING_HINTS)) and "EMAIL_PROVIDER" not in tags:
        tags.append("HOSTING/CLOUD")
    if g.get("mobile") or _has(isp, MOBILE_HINTS):
        tags.append("MOBILE/RESIDENTIAL")
    if _has(isp, GOV_HINTS):
        tags.append("GOVERNMENT")
    if _has(isp, BULLETPROOF_HINTS):
        tags.append("BULLETPROOF_SUSPECT")
    if not tags:
        tags.append("RESIDENTIAL/ISP")
    # infrastructure category
    if "TOR_EXIT" in tags:
        cat, anon = "anonymised (Tor)", 0.95
    elif "EMAIL_PROVIDER" in tags:
        cat, anon = "email service provider (client IP withheld)", 0.5
    elif "PROXY/VPN" in tags or "VPN_PROVIDER" in tags:
        cat, anon = "anonymised (VPN/proxy)", 0.8
    elif "BULLETPROOF_SUSPECT" in tags:
        cat, anon = "bulletproof / abuse-tolerant hosting", 0.7
    elif "GOVERNMENT" in tags:
        cat, anon = "government network", 0.05
    elif "HOSTING/CLOUD" in tags:
        cat, anon = "cloud / rented server", 0.4
    elif "MOBILE/RESIDENTIAL" in tags:
        cat, anon = "mobile / residential endpoint", 0.1
    else:
        cat, anon = "ISP / residential", 0.1
    return {"tags": tags, "category": cat, "anonymity_score": anon}

def geo_precision(rec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Honest precision envelope for a GeoIP record.

    The platform never invents coordinates: a record is only 'city' precision when the provider
    actually returned a city AND coordinates, 'country' precision when only the country is known
    (no coordinates → the UI must say so and must not place a pin), and 'unknown' when nothing
    resolved. Anonymising infrastructure (Tor/VPN/proxy) drives the confidence down further
    because the *geographic* position of the IP says nothing about the operator's position.
    """
    def _num(v):
        try:
            f = float(v)
        except (TypeError, ValueError):
            return None
        return f if f == f else None                      # NaN guard

    lat, lon = _num(rec.get("lat")), _num(rec.get("lon"))
    has_coords = lat is not None and lon is not None and abs(lat) <= 90.0 and abs(lon) <= 180.0 and (lat or lon)
    city = (rec.get("city") or "").strip()
    region = (rec.get("regionName") or "").strip()
    country = (rec.get("country") or "").strip()
    status = rec.get("status") or "unknown"
    anon = rec.get("anonymity_score") or 0.0

    if status == "private":
        return {"level": "private", "label": "Private / internal network", "radius_km": None,
                "has_coordinates": False, "approximate": True, "confidence": 1.0,
                "caveat": "RFC1918 address — not routable on the public internet"}
    if status not in ("success", "seed") or (not country and not has_coords):
        return {"level": "unknown", "label": "Location unavailable", "radius_km": None,
                "has_coordinates": False, "approximate": True, "confidence": 0.0,
                "caveat": "No GeoIP answer for this address (lookup failed / offline / private)"}
    if has_coords and city:
        level, radius, conf = "city", 25, 0.88
    elif has_coords and region:
        level, radius, conf = "region", 120, 0.72
    elif has_coords:
        level, radius, conf = "country", 600, 0.55
    else:                                                  # country known, coordinates genuinely missing
        level, radius, conf = "country", None, 0.40

    caveat = ""
    if not has_coords:
        caveat = "Coordinates unavailable — country-level location only, no pin plotted"
    if anon >= 0.7:
        conf *= 0.30
        caveat = "Infrastructure is anonymising (Tor/VPN/proxy): the IP location is not the actor's location"
    elif anon >= 0.4:
        conf *= 0.60
        caveat = caveat or "Rented/anonymised infrastructure — location is indicative only"
    if status == "seed":
        conf *= 0.85
        caveat = caveat or "Bundled offline seed record (no live lookup)"

    loc = ", ".join([x for x in (city, region, country) if x]) or "Unknown"
    label = {"city": "City-level", "region": "Region-level", "country": "Country-level",
             "private": "Private network", "unknown": "Location unavailable"}[level]
    return {"level": level, "label": label + (" (approximate)" if level in ("region", "country") else ""),
            "radius_km": radius, "has_coordinates": bool(has_coords), "approximate": level in ("region", "country", "unknown"),
            "confidence": round(max(0.0, min(0.95, conf)), 2), "location": loc, "caveat": caveat}


GEO_URL = "http://ip-api.com/batch?fields=status,message,query,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"

class _GeoBatcher:
    """
    Coalesces concurrent geolocation requests (8 ingestion workers × 1-4 IPs each) into ONE ip-api batch call
    (≤100 IPs) per ~300 ms window, and honours the service's 45 requests/minute budget (X-Rl / X-Ttl headers).
    Without this, a 1,000-email import would fire ~1,000 requests and get throttled after the first minute.
    """
    def __init__(self):
        self.lock = threading.Lock(); self.pending: set = set(); self.event: Optional[threading.Event] = None
        self.blocked_until = 0.0

    def _request(self, batch: List[str]) -> None:
        wait = self.blocked_until - time.time()
        if wait > 0:
            time.sleep(min(wait, 65))
        try:
            r = httpx.post(GEO_URL, json=batch, timeout=12)
            if r.status_code == 200:
                for rec in r.json():
                    q = rec.get("query")
                    if not q: continue
                    if rec.get("status") == "success":
                        _cset(f"geo:{q}", rec)
                    else:
                        _cset(f"geo:{q}", {"query": q, "status": "fail", "message": rec.get("message", "")}, transient=True)
                try:
                    if int(r.headers.get("X-Rl", "1")) <= 1:
                        self.blocked_until = time.time() + int(r.headers.get("X-Ttl", "60")) + 1
                except ValueError:
                    pass
            elif r.status_code == 429:
                self.blocked_until = time.time() + int(r.headers.get("X-Ttl", "60") or 60) + 1
        except Exception:
            pass

    def fetch(self, todo: List[str]) -> None:
        """Blocks until every IP in `todo` is in the cache (success or negative) or ~3 windows have passed."""
        for _round in range(3):
            with self.lock:
                self.pending.update(todo)
                leader = self.event is None
                if leader: self.event = threading.Event()
                ev = self.event
            if leader:
                time.sleep(0.3)
                with self.lock:
                    batch = sorted(self.pending)[:100]; self.pending.difference_update(batch); self.event = None
                if batch: self._request(batch)
                ev.set()
            else:
                ev.wait(25)
            todo = [ip for ip in todo if _cache.get(f"geo:{ip}") is None]
            if not todo:
                return

_geo_batcher = _GeoBatcher()

def geolocate(ips: List[str], live: bool = True) -> Dict[str, Dict[str, Any]]:
    """Batch geolocate. Returns {ip: record}. Never raises. live=False → cache/seed only (triage pass)."""
    out: Dict[str, Dict[str, Any]] = {}
    todo = []
    for ip in ips:
        if not valid_ip(ip):
            continue
        if is_private_ip(ip):
            out[ip] = {"query": ip, "status": "private", "country": "Private/Internal", "countryCode": "--", "city": "", "isp": "Internal network", "lat": None, "lon": None}
            continue
        c = _cget(f"geo:{ip}", ttl=86400 * 7)
        if c and c.get("status") == "success":
            out[ip] = dict(c)
        elif c and c.get("status") == "fail":
            pass                                              # negative-cached → seed / unknown below
        else:
            todo.append(ip)
    if todo and live and not OFFLINE and HTTP_OK:
        _geo_batcher.fetch(todo)
        for ip in todo:
            c = _cget(f"geo:{ip}", ttl=86400 * 7)
            if c and c.get("status") == "success":
                out[ip] = dict(c)
    for ip in todo:
        if ip not in out:
            seed = _SEED.get(ip)
            if seed:
                out[ip] = dict(seed, query=ip, status="seed")
            else:
                out[ip] = {"query": ip, "status": "unknown", "country": "Unknown", "countryCode": "??", "city": "", "isp": "Unknown (offline)", "lat": None, "lon": None}
    for ip, rec in out.items():
        if "e-mail" in str(rec.get("isp", "")).lower() or "@" in str(rec.get("isp", "")):
            rec["isp"] = (rec.get("as", "").split(" ", 1)[-1] if rec.get("as") and " " in rec.get("as") else "") or rec.get("org") or rec.get("asname") or rec["isp"]
        rec.update(classify_ip(rec))
        rec["is_tor"] = ip in _TOR
        # precision envelope — downstream code (scoring, attribution, UI) must never claim more than this
        rec["geo_precision"] = geo_precision(rec)
        rec["location_label"] = rec["geo_precision"].get("location") or ", ".join(
            x for x in (rec.get("city"), rec.get("regionName"), rec.get("country")) if x) or "Unknown"
    return out

# ------------------------------------------------------------------ RDAP ---
def _http_json(url: str, ttl=86400 * 3):
    if OFFLINE or not HTTP_OK:
        return None
    ck = f"http:{url}"
    c = _cget(ck, ttl)
    if c is not None:
        return c or None
    transient = False
    try:
        r = httpx.get(url, timeout=8, follow_redirects=True, headers={"Accept": "application/rdap+json, application/json"})
        if r.status_code in (429, 500, 502, 503, 504):        # rate-limited: brief back-off, one retry, never cache as "not found"
            try: delay = min(float(r.headers.get("Retry-After", "2")), 5.0)
            except ValueError: delay = 2.0
            time.sleep(delay)
            r = httpx.get(url, timeout=8, follow_redirects=True, headers={"Accept": "application/rdap+json, application/json"})
        if r.status_code == 200:
            v = r.json()
        else:
            v = {}; transient = r.status_code != 404
    except Exception:
        v = {}; transient = True
    _cset(ck, v, transient=transient)
    return v or None

def domain_rdap(domain: str) -> Dict[str, Any]:
    dom = registered_domain(domain)
    res: Dict[str, Any] = {"domain": dom, "found": False}
    if not dom or valid_ip(dom):
        return res
    seed = _SEED.get("domains", {}).get(dom) if isinstance(_SEED.get("domains"), dict) else None
    j = _http_json(f"https://rdap.org/domain/{dom}")
    if not j:
        if seed:
            res.update(seed, found=True, source="demo-seed")
            if res.get("created"):
                try:
                    from datetime import datetime, timezone
                    c = datetime.fromisoformat(res["created"].replace("Z", "+00:00"))
                    res["age_days"] = (datetime.now(timezone.utc) - c).days
                except Exception:
                    pass
            res["resolves"] = True
        else:
            res["note"] = "RDAP lookup failed / TLD has no RDAP / domain not registered"
            res["resolves"] = bool(_a(dom)) or bool(get_mx(dom))
        return res
    res["found"] = True; res["source"] = "rdap"
    for e in j.get("events", []):
        a = e.get("eventAction", "")
        if a == "registration": res["created"] = e.get("eventDate")
        elif a == "expiration": res["expires"] = e.get("eventDate")
        elif a == "last changed": res["updated"] = e.get("eventDate")
    for ent in j.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for x in ent.get("vcardArray", [None, []])[1]:
                if x[0] == "fn": res["registrar"] = x[3]
        if "registrant" in ent.get("roles", []):
            for x in ent.get("vcardArray", [None, []])[1]:
                if x[0] == "fn" and x[3]: res["registrant"] = x[3]
                if x[0] == "adr" and isinstance(x[3], list): res["registrant_country"] = x[3][-1]
    res["nameservers"] = [n.get("ldhName", "").lower() for n in j.get("nameservers", [])][:6]
    res["status"] = j.get("status", [])
    res["privacy_proxy"] = any("privacy" in str(s).lower() or "redacted" in str(s).lower() or "proxy" in str(s).lower() for s in [res.get("registrant", "")] + [str(ent.get("vcardArray")) for ent in j.get("entities", [])][:3])
    if res.get("created"):
        try:
            from datetime import datetime, timezone
            c = datetime.fromisoformat(res["created"].replace("Z", "+00:00"))
            res["age_days"] = (datetime.now(timezone.utc) - c).days
        except Exception:
            pass
    res["resolves"] = bool(_a(dom)) or bool(get_mx(dom))
    return res

def ip_rdap(ip: str) -> Dict[str, Any]:
    res: Dict[str, Any] = {"ip": ip, "found": False}
    if not valid_ip(ip) or is_private_ip(ip):
        return res
    j = _http_json(f"https://rdap.org/ip/{ip}")
    if not j:
        return res
    res.update(found=True, netname=j.get("name"), country=j.get("country"), start=j.get("startAddress"), end=j.get("endAddress"), handle=j.get("handle"))
    abuse = []
    for ent in j.get("entities", []):
        roles = ent.get("roles", [])
        names = [x[3] for x in ent.get("vcardArray", [None, []])[1] if x[0] in ("fn",)]
        mails = [x[3] for x in ent.get("vcardArray", [None, []])[1] if x[0] == "email"]
        if "abuse" in roles:
            abuse += mails
        if "registrant" in roles and names and not res.get("org"):
            res["org"] = names[0]
        for sub in ent.get("entities", []):
            if "abuse" in sub.get("roles", []):
                abuse += [x[3] for x in sub.get("vcardArray", [None, []])[1] if x[0] == "email"]
    for rem in j.get("remarks", []):
        for d in rem.get("description", []):
            if "abuse" in d.lower() and "@" in d:
                abuse += re.findall(r"[\w.+-]+@[\w.-]+", d)
    res["abuse_contacts"] = sorted(set(abuse))[:3]
    rir = ""
    for l in j.get("links", []):
        if "ripe" in l.get("href", ""): rir = "RIPE NCC"
        elif "arin" in l.get("href", ""): rir = "ARIN"
        elif "apnic" in l.get("href", ""): rir = "APNIC"
        elif "afrinic" in l.get("href", ""): rir = "AFRINIC"
        elif "lacnic" in l.get("href", ""): rir = "LACNIC"
    res["rir"] = rir
    return res
