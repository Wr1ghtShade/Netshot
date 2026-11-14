"""
core/criminalip.py - Criminal IP (key "criminalip", free account: 50 IP lookups and 100 URL scans per
month), run with the reputation of the host names. Credits are scarce, so each scan spends little:

- IP: /v1/feature/ip/suspicious-info on the first --criminalip-ips public IPs (default 5), those that
  carry the most services first: inbound / outbound score, VPN / Tor / proxy / scanner / Snort tags,
  abuse records.
- domain: one "lite" scan (/v1/domain/lite/scan, then progress, then report) on the first
  --criminalip-domains registrable domains (default 1), the most scanned first: domain score,
  phishing probability, malware / phishing classification, punycode, fake https.

Internal IPs and names that resolve to internal IPs are never sent. Same behaviour as criminalip.go
(netshot-go).
"""

import ipaddress
import json
import time
import urllib.parse
from collections import Counter

from .sources import is_internal_ip, registrable_domain

CIP_BASE = "https://api.criminalip.io"
DEFAULT_IPS = 5      # free account: 50 IP lookups per month
DEFAULT_DOMAINS = 1  # free account: 100 domain scans per month
SEVERITY_ORDER = {"critique": 0, "haute": 1, "moyenne": 2, "info": 3}


class CIPError(RuntimeError):
    """stop=True: key refused or credits exhausted, no use going on."""

    def __init__(self, msg, stop=False):
        super().__init__(msg)
        self.stop = stop


def _get(path, params, key):
    from .reputation import _http  # late import: reputation imports this module
    url = CIP_BASE + path + ("?" + urllib.parse.urlencode(params) if params else "")
    status, body = _http("GET", url, {"x-api-key": key, "Accept": "application/json"})
    try:
        data = json.loads(body or b"{}")
    except ValueError:
        data = {}
    code = status
    if status == 200 and isinstance(data, dict) and data.get("status"):
        code = data["status"]
    if code == 200:
        return data
    if code == 401:
        raise CIPError("Criminal IP : clé refusée (HTTP 401)", True)
    if code in (403, 429):
        raise CIPError(f"Criminal IP : crédits épuisés ou limite atteinte (HTTP {code})", True)
    msg = (data.get("message") if isinstance(data, dict) else "") or f"HTTP {code}"
    raise CIPError(f"Criminal IP : {msg}")


def cip_score(v):
    """A score given as a word ("Dangerous") or a number (1 safe ... 5 critical)."""
    if isinstance(v, str) and v.strip().isdigit():
        v = int(v)
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return {1: "safe", 2: "low", 3: "moderate", 4: "dangerous", 5: "critical"}.get(int(v), "")
    return str(v or "").strip().lower()


def cip_level(score):
    s = (score or "").lower()
    if "critical" in s:
        return "critique"
    if "dangerous" in s:
        return "haute"
    if "moderate" in s:
        return "moyenne"
    return ""


def worse(a, b):
    """The more severe of two levels ('' = nothing)."""
    rank = lambda l: SEVERITY_ORDER.get(l, len(SEVERITY_ORDER))
    return b if rank(b) < rank(a) else a


def cip_ip(ip, key):
    """-> (summary, level) from the outbound score (what the IP does) and the inbound one (what it receives)."""
    res = _get("/v1/feature/ip/suspicious-info", {"ip": ip}, key)
    score = res.get("score") or {}
    inb, outb = cip_score(score.get("inbound")), cip_score(score.get("outbound"))
    tags = sorted(k.removeprefix("is_") for k, v in (res.get("issues") or {}).items() if v is True)
    parts = [f"score entrant {inb or '-'}, sortant {outb or '-'}"]
    if tags:
        parts.append(", ".join(tags))
    if res.get("abuse_record_count"):
        parts.append(f"{res['abuse_record_count']} signalement(s) d'abus")
    return " ; ".join(parts), worse(cip_level(outb), cip_level(inb))


def _types(v):
    if isinstance(v, list):
        return [t for x in v for t in _types(str(x))]
    return [s.strip().lower() for s in str(v or "").split(",") if s.strip() and s.strip().lower() != "none"]


def cip_domain(domain, key, stop=None):
    """Lite scan of a domain and its report (about 10 to 60 s) -> (summary, level)."""
    scan_id = ((_get("/v1/domain/lite/scan", {"query": domain}, key).get("data") or {}).get("scan_id"))
    if scan_id in (None, ""):
        raise CIPError(f"Criminal IP : pas d'identifiant d'analyse pour {domain}")
    if isinstance(scan_id, float):
        scan_id = int(scan_id)
    deadline = time.monotonic() + 180
    while True:
        pct = ((_get("/v1/domain/lite/progress", {"scan_id": scan_id}, key).get("data") or {})
               .get("scan_percentage", 0)) or 0
        if pct >= 100:
            break
        if pct < 0:
            raise CIPError(f"Criminal IP : analyse de {domain} en échec")
        if time.monotonic() > deadline:
            raise CIPError(f"Criminal IP : analyse de {domain} trop longue (abandon après 3 min)")
        if stop and stop.wait(3):
            raise CIPError("Criminal IP : scan arrêté", True)
        if not stop:
            time.sleep(3)
    d = _get(f"/v1/domain/lite/report/{urllib.parse.quote(str(scan_id))}", None, key).get("data") or {}
    summ, cls = d.get("summary") or {}, d.get("classification") or {}
    level = cip_level(d.get("domain_score", ""))
    parts = [f"score du domaine {d.get('domain_score') or '-'}"]
    types = _types(cls.get("domain_type"))
    if any(t in ("malware", "phishing") for t in types):
        level = worse(level, "critique")
    if types:
        parts.append("catégorie " + ", ".join(types))
    prob = summ.get("url_phishing_prob") or 0
    if prob:
        parts.append(f"probabilité de phishing {prob:.0f} %")
        if prob >= 70:
            level = worse(level, "haute")
    if summ.get("fake_https_url"):
        parts.append("faux lien https")
        level = worse(level, "haute")
    if summ.get("punycode"):
        parts.append("punycode")
    ab = summ.get("abuse_record") or {}
    if sum(ab.get(k, 0) or 0 for k in ("critical", "dangerous", "moderate")):
        parts.append(f"IP liées signalées : {ab.get('critical', 0)} critique(s), {ab.get('dangerous', 0)} "
                     f"dangereuse(s), {ab.get('moderate', 0)} modérée(s)")
    return " ; ".join(parts), level


def _public_ip(text):
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return not is_internal_ip(text)


def check_criminalip(reps, names, exposures, results, key, max_ips=DEFAULT_IPS, max_domains=DEFAULT_DOMAINS,
                     log=print, stop=None):
    """Adds the Criminal IP findings to the reputation rows: the domain report on the row of that domain
    (created when the domain itself was not scanned), one row per IP looked up."""
    if not key or (max_ips <= 0 and max_domains <= 0):
        return reps
    by_host = {r["host"]: r for r in reps}
    count = Counter(registrable_domain(n) for n in names)
    domains = sorted(count, key=lambda d: (-count[d], d))[:max(0, max_domains)]
    hosts_of = {}
    for x in exposures or []:
        if x.get("internal") or not _public_ip(x["ip"]):
            continue
        lst = hosts_of.setdefault(x["ip"], [])
        lst += [h for h in x["hosts"] if h not in lst]
    services = Counter()
    for r in results:
        h = r["host"].strip("[]")
        if _public_ip(h):
            hosts_of.setdefault(h, [])
            services[h] += 1
            continue
        for ip, hs in hosts_of.items():
            if r["host"] in hs:
                services[ip] += 1
    ips = sorted(hosts_of, key=lambda ip: (-services[ip], ip))
    skipped = max(0, len(ips) - max(0, max_ips))
    ips = ips[:max(0, max_ips)]
    if not domains and not ips:
        return reps
    log(f"[criminalip] {len(domains)} domaine(s), {len(ips)} IP (offre gratuite : 100 analyses de domaine "
        f"et 50 IP par mois)")
    if skipped:
        log(f"[criminalip] {skipped} autre(s) IP publique(s) non vérifiée(s) (limite --criminalip-ips {max_ips})")
    halt = False
    for d in domains:
        if halt or (stop and stop.is_set()):
            break
        r = by_host.get(d)
        if r is None:
            r = {"host": d, "level": "", "blocked_by": [], "urlhaus": "", "errors": []}
            by_host[d] = r
            reps.append(r)
        try:
            r["criminalip"], r["criminalip_level"] = cip_domain(d, key, stop)
        except (CIPError, OSError, ValueError) as exc:
            r["errors"].append(str(exc))
            log(f"[criminalip] {d} : {exc}")
            halt = getattr(exc, "stop", False)
    for ip in ips:
        if halt or (stop and stop.is_set()):
            break
        try:
            s, level = cip_ip(ip, key)
        except (CIPError, OSError, ValueError) as exc:
            log(f"[criminalip] {ip} : {exc}")
            halt = getattr(exc, "stop", False)
            continue
        reps.append({"host": ip, "level": "", "blocked_by": [], "urlhaus": "", "errors": [],
                     "criminalip": s, "criminalip_level": level, "names": hosts_of[ip]})
    return reps
