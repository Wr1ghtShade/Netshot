"""
core/reputation.py - Reputation of the host names found (checks inspired by web-check: "Block
Detection" and "Malware & Phishing"), run with the enrichment (--no-enrich turns it off).

- filtering DNS resolvers: Quad9 (threats), Cloudflare 1.1.1.2 (malware), OpenDNS (phishing),
  AdGuard DNS (ads and trackers), each compared with an unfiltered answer. No key.
- URLhaus (abuse.ch, free key "abusech"): malicious URLs known on the host, Spamhaus DBL / SURBL
- VirusTotal (key "virustotal", already used for the subdomains): engines flagging the domain
- Google Safe Browsing (free key "safebrowsing"): malware, phishing, unwanted software

Only public host names are sent: a name that resolves to an internal IP never leaves the machine.
Same behaviour as reputation.go (netshot-go).
"""

import csv
import html
import ipaddress
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import __version__
from .dns import query as dns_query
from .recon import SEVERITY, _sev as sev_badge

# name, server, what it blocks, sinkhole answers (besides NXDOMAIN and 0.0.0.0), blocks threats
DNS_FILTERS = [
    ("Quad9", "9.9.9.9", "malware / phishing", [], True),
    ("Cloudflare 1.1.1.2", "1.1.1.2", "malware", [], True),
    ("OpenDNS", "208.67.222.222", "phishing",
     ["146.112.61.104", "146.112.61.105", "146.112.61.106", "146.112.61.107", "146.112.61.108", "146.112.61.110"], True),
    ("AdGuard DNS", "94.140.14.14", "publicité / traqueurs", ["94.140.14.33", "94.140.14.35"], False),
]
UNFILTERED_DNS = ["1.1.1.1", "9.9.9.10"]  # reference answer
MAX_VIRUSTOTAL = 8  # free API: 4 requests per minute
UNREACHABLE = "résolveurs DNS publics injoignables (port 53 sortant filtré ?)"


def _a_records(server, name):
    """-> (IPs, rcode); NXDOMAIN gives rcode 3. Raises OSError when the server does not answer."""
    recs, rcode = dns_query(server, 53, name, 1, timeout=3.0)
    return [r["data"] for r in recs if r["type"] == "A"], rcode


def dns_blocks(name):
    """-> (filtering resolvers that block name, resolvers that did not answer)."""
    ref = None
    for s in UNFILTERED_DNS:
        try:
            ips, rcode = _a_records(s, name)
        except (OSError, ValueError):
            continue
        ref = ips if rcode == 0 else []
        break
    if ref is None:
        return [], [UNREACHABLE]
    if not ref:
        return [], []  # the name does not resolve: nothing to compare

    def one(f):
        fname, server, blocks, sinkholes, _ = f
        try:
            ips, rcode = _a_records(server, name)
        except (OSError, ValueError):
            return None, f"{fname} injoignable"
        is_block = rcode == 3 or any(ip in ("0.0.0.0", "127.0.0.1") or ip in sinkholes for ip in ips)
        return (f"{fname} ({blocks})" if is_block else None), None

    with ThreadPoolExecutor(len(DNS_FILTERS)) as pool:
        res = list(pool.map(one, DNS_FILTERS))
    return sorted(b for b, _ in res if b), sorted(e for _, e in res if e)


def _http(method, url, headers=None, data=None, timeout=20):
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"User-Agent": f"netshot/{__version__}", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(8 << 20)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(65536)


def urlhaus_host(host, key):
    """-> (summary, at least one URL online)."""
    status, body = _http("POST", "https://urlhaus-api.abuse.ch/v1/host/",
                         {"Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded"},
                         urllib.parse.urlencode({"host": host}).encode())
    if status != 200:
        raise RuntimeError(f"URLhaus HTTP {status}")
    data = json.loads(body)
    if data.get("query_status") != "ok":
        if data.get("query_status") in ("no_results", "invalid_host"):
            return "", False
        raise RuntimeError(f"URLhaus : {data.get('query_status')}")
    urls = data.get("urls") or []
    online = sum(u.get("url_status") == "online" for u in urls)
    threats = sorted({u["threat"] for u in urls if u.get("threat")})
    parts = []
    if urls:
        s = f"{len(urls)} URL malveillante(s) dont {online} en ligne"
        if threats:
            s += f" ({', '.join(threats)})"
        parts.append(s)
    for k in ("spamhaus_dbl", "surbl"):
        v = (data.get("blacklists") or {}).get(k, "")
        if v and v != "not listed":
            parts.append(f"{k} : {v}")
    return " ; ".join(parts), online > 0


def virustotal_domain(domain, key):
    """-> (summary, engines saying malicious)."""
    status, body = _http("GET", "https://www.virustotal.com/api/v3/domains/" + urllib.parse.quote(domain, safe=""),
                         {"x-apikey": key})
    if status == 404:
        return "", 0
    if status != 200:
        raise RuntimeError(f"VirusTotal HTTP {status}")
    st = json.loads(body).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
    mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
    if not mal and not sus:
        return "", 0
    return f"{mal} malveillant(s), {sus} suspect(s) / {sum(st.values())} moteurs", mal


def safe_browsing(urls, key):
    """Lookup API v4, one request: url -> [threat types]."""
    body = json.dumps({
        "client": {"clientId": "netshot", "clientVersion": __version__},
        "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                       "POTENTIALLY_HARMFUL_APPLICATION"],
                       "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                       "threatEntries": [{"url": u} for u in urls]},
    }).encode()
    try:
        status, data = _http("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
                             + urllib.parse.quote(key), {"Content-Type": "application/json"}, body)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Safe Browsing : {exc.reason}") from None  # never show the URL with the key
    if status != 200:
        raise RuntimeError(f"Safe Browsing HTTP {status}")
    out = {}
    for m in json.loads(data).get("matches") or []:
        u, t = m.get("threat", {}).get("url", ""), m.get("threatType", "")
        if t and t not in out.setdefault(u, []):
            out[u].append(t)
    return out


def reputation_level(r, urlhaus_online=False):
    security = any(b.startswith(f[0] + " ") for b in r["blocked_by"] for f in DNS_FILTERS if f[4])
    if r["safe_browsing"] or urlhaus_online or r["vt_malicious"] >= 3:
        return "critique"
    if security or r["urlhaus"] or r["vt_malicious"] > 0:
        return "haute"
    if r["virustotal"]:
        return "moyenne"
    if r["blocked_by"]:
        return "info"
    return ""


def level_rank(level):
    """critique < haute < moyenne < info < nothing found."""
    return SEVERITY.get(level, len(SEVERITY))


def summary(r):
    parts = []
    if r["blocked_by"]:
        parts.append("bloqué par " + ", ".join(r["blocked_by"]))
    if r["urlhaus"]:
        parts.append("URLhaus : " + r["urlhaus"])
    if r["virustotal"]:
        parts.append("VirusTotal : " + r["virustotal"])
    if r["safe_browsing"]:
        parts.append("Safe Browsing : " + ", ".join(r["safe_browsing"]))
    return " ; ".join(parts)


def _is_ip(text):
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        return False


def check_reputation(results, exposures, keys, log=print, stop=None):
    """Looks up the public host names of the scan. Names of internal IPs are skipped."""
    internal, public = set(), set()
    for x in exposures or []:
        for h in x["hosts"]:
            (internal if x["internal"] else public).add(h)
    urls_by_host = {}
    for r in results:
        h = r["host"].lower()
        if _is_ip(h) or r["host"] in internal or r["host"] not in public:
            continue
        lst = urls_by_host.setdefault(h, [])
        for u in (r.get("url"), r.get("final_url")):
            if u and u not in lst:
                lst.append(u)
    names = sorted(urls_by_host)
    if not names:
        return []
    abusech, vt, sb = keys.get("abusech", ""), keys.get("virustotal", ""), keys.get("safebrowsing", "")
    srcs = ["résolveurs filtrants (Quad9, Cloudflare, OpenDNS, AdGuard)"]
    srcs += [n for n, k in (("URLhaus", abusech), ("VirusTotal", vt), ("Safe Browsing", sb)) if k]
    log(f"[réputation] {len(names)} nom(s) public(s) : {', '.join(srcs)}")

    reps = {n: {"host": n, "level": "", "blocked_by": [], "urlhaus": "", "virustotal": "", "vt_malicious": 0,
                "safe_browsing": [], "errors": []} for n in names}
    online = {}

    def one(n):
        r = reps[n]
        r["blocked_by"], r["errors"] = dns_blocks(n)
        if abusech and not (stop and stop.is_set()):
            try:
                r["urlhaus"], online[n] = urlhaus_host(n, abusech)
            except (RuntimeError, OSError, ValueError) as exc:
                r["errors"].append(str(exc))

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(one, names))
    if vt:
        for i, n in enumerate(names):
            if stop and stop.is_set():
                break
            if i == MAX_VIRUSTOTAL:
                log(f"[réputation] VirusTotal limité aux {MAX_VIRUSTOTAL} premiers noms (API gratuite : 4 requêtes / minute)")
                break
            if i:
                time.sleep(15)
            try:
                reps[n]["virustotal"], reps[n]["vt_malicious"] = virustotal_domain(n, vt)
            except (RuntimeError, OSError, ValueError) as exc:
                reps[n]["errors"].append(str(exc))
    if sb and not (stop and stop.is_set()):
        all_urls = [u for n in names for u in urls_by_host[n]]
        for start in range(0, len(all_urls), 500):
            try:
                matches = safe_browsing(all_urls[start:start + 500], sb)
            except (RuntimeError, OSError, ValueError) as exc:
                log(f"[réputation] {exc}")
                break
            for n in names:
                for u in urls_by_host[n]:
                    for t in matches.get(u, []):
                        if t not in reps[n]["safe_browsing"]:
                            reps[n]["safe_browsing"].append(t)
    if all(UNREACHABLE in reps[n]["errors"] for n in names):
        log(f"[réputation] listes de blocage non vérifiées : {UNREACHABLE}")
    out = []
    for n in names:
        r = reps[n]
        r["level"] = reputation_level(r, online.get(n, False))
        if r["level"]:
            log(f"[réputation] {n}  {r['level']}  {summary(r)}")
        out.append(r)
    out.sort(key=lambda r: level_rank(r["level"]))
    return out


def write_reputation_csv(reps, path):
    if not reps:
        return
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "level", "blocked_by", "urlhaus", "virustotal", "vt_malicious", "safe_browsing", "errors"])
        for r in reps:
            w.writerow([r["host"], r["level"], "; ".join(r["blocked_by"]), r["urlhaus"], r["virustotal"],
                        r["vt_malicious"], " ".join(r["safe_browsing"]), "; ".join(r["errors"])])


def reputation_section(reps):
    if not reps:
        return ""
    rows = [f"<tr><td>{sev_badge(r['level'])}</td><td>{html.escape(r['host'])}</td>"
            f"<td>{html.escape(summary(r))}</td></tr>" for r in reps if r["level"]]
    if not rows:
        return (f"<p><b>Réputation</b> : {len(reps)} nom(s) vérifié(s), aucun sur une liste de blocage "
                f"ou de menaces.</p>")
    return (f"<details open><summary><b>Réputation (listes de blocage, malware, phishing)</b> - {len(rows)} nom(s) "
            f"signalé(s) sur {len(reps)}</summary><table><tr><th>Niveau</th><th>Nom</th><th>Constat</th></tr>"
            f"{''.join(rows)}</table></details>")
