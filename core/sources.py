"""
core/sources.py - Passive sources and target imports for netshot.

- API keys of the free services (keys.json in the application folder)
- subdomain sources: CT logs, passive DNS, web archives
- IPv4 prefixes announced by an AS (RIPEstat)
- CSV import (Active Directory, ADCS, CMDB exports)

Only domain names, AS numbers and public IPs are sent to these services: nothing is
sent to the scanned hosts. urllib uses the Windows system proxy automatically.
"""

import csv
import io
import ipaddress
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import ASSETS, ROOT

# --- API keys ----------------------------------------------------------------

KEY_SOURCES = [
    ("certspotter", "Cert Spotter", "https://sslmate.com/signup?for=ct_search_api"),
    ("hackertarget", "HackerTarget", "https://hackertarget.com/scan-membership/"),
    ("urlscan", "urlscan.io", "https://urlscan.io/user/signup"),
    ("virustotal", "VirusTotal", "https://www.virustotal.com/gui/join-us"),
    ("dnsdumpster", "DNSDumpster", "https://dnsdumpster.com/"),
    ("domscan", "DomScan", "https://domscan.net/pricing"),
    ("viewdns", "ViewDNS", "https://viewdns.info/api/pricing/"),
    ("leakix", "LeakIX", "https://leakix.net/"),
    ("shodan", "Shodan", "https://account.shodan.io/"),
    ("leakcheck", "LeakCheck", "https://leakcheck.io/"),
    ("nvd", "NVD (NIST)", "https://nvd.nist.gov/developers/request-an-api-key"),
    ("abusech", "abuse.ch (URLhaus)", "https://auth.abuse.ch/"),
]


def keys_path():
    """keys.json in the application folder (next to netshot.py). Do not share the folder with its keys."""
    return ROOT / "keys.json"


def ensure_keys_file():
    """Create an empty keys.json template in the application folder when it is missing.
    Exclusive creation ("x"): an existing keys.json is never overwritten."""
    path = keys_path()
    if path.exists():
        return
    content = json.dumps({name: "" for name, _, _ in KEY_SOURCES}, indent=2)
    try:
        with open(path, "x", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, 0o600)
    except OSError:
        pass  # already created meanwhile, or read-only folder: run without file


def load_keys():
    """Saved keys, overridden by NETSHOT_KEY_<SOURCE> environment variables."""
    ensure_keys_file()
    keys = {}
    try:
        keys = json.loads(keys_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    if os.environ.get("CERTSPOTTER_API_KEY"):  # kept for compatibility
        keys["certspotter"] = os.environ["CERTSPOTTER_API_KEY"]
    for name, _, _ in KEY_SOURCES:
        value = os.environ.get(f"NETSHOT_KEY_{name.upper()}")
        if value:
            keys[name] = value
    return keys


def update_keys(changes):
    """Apply changes to keys.json as it is on disk now: {name: value} sets a key, {name: None} removes it.
    Keys not named in changes are kept as in the file (never replaced by a copy held in memory, nor by
    environment variables). An unreadable file is never rewritten (ValueError). The previous file is kept
    as keys.json.bak, and the new one replaces it in one step (no half-written file)."""
    path = keys_path()
    current = {}
    if path.exists():
        try:
            current = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise ValueError(f"{path} n'est pas un JSON valide, corrige-le avant d'enregistrer ({exc})")
        if not isinstance(current, dict):
            raise ValueError(f"{path} doit contenir un objet JSON")
    for name, value in changes.items():
        value = (value or "").strip()
        if value:
            current[name] = value
        else:
            current.pop(name, None)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = path.with_name("keys.json.bak")
        backup.write_bytes(path.read_bytes())
        try:
            os.chmod(backup, 0o600)
        except OSError:
            pass
    tmp = path.with_name("keys.json.tmp")
    tmp.write_text(json.dumps(current, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


# --- HTTP helpers --------------------------------------------------------------

def _get(url, timeout, headers=None):
    """GET url, return (status, body). HTTP errors are returned, not raised."""
    req = urllib.request.Request(url, headers={"User-Agent": "netshot", "Accept": "application/json",
                                               **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def get_json(source, url, headers=None, timeout=60):
    """Fetch and decode JSON, turning HTTP errors into readable messages."""
    try:
        status, body = _get(url, timeout, headers)
    except (socket.timeout, TimeoutError):
        raise RuntimeError(f"{source}: no answer after {timeout} s")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{source}: {exc.reason}")
    if status == 429:
        raise RuntimeError(f"{source}: quota or rate limit reached")
    if status in (401, 403):
        raise RuntimeError(f"{source}: key refused or missing (HTTP {status})")
    if status != 200:
        raise RuntimeError(f"{source}: HTTP {status}: {body[:150].decode(errors='replace').strip()}")
    try:
        return json.loads(body)
    except ValueError as exc:
        raise RuntimeError(f"{source}: unexpected answer: {exc}")


def _require(source, key):
    if not key:
        raise RuntimeError(f"{source}: API key required (free account)")


# --- Subdomain sources -------------------------------------------------------------
# Each fetcher takes (domain, key) and returns raw names; cleaning happens in ct_lookup.

def fetch_crt_name(domain, key=""):
    """crt.name index: CT logs plus other public sources. The domain must be an apex."""
    rows = get_json("crt.name", "https://crt.name/v1/search?format=json&apex=" + urllib.parse.quote(domain))
    return [r.get("sub", "") for r in rows]


def fetch_crt_sh(domain, key=""):
    """crt.sh, often slow or overloaded: 30 s per attempt, one retry."""
    url = "https://crt.sh/?q=" + urllib.parse.quote("%." + domain) + "&output=json"
    last = None
    for attempt in (1, 2):
        try:
            names = []
            for row in get_json("crt.sh", url, timeout=30):
                names += str(row.get("name_value", "")).split("\n")
                names.append(str(row.get("common_name", "")))
            return names
        except RuntimeError as exc:
            last = exc
            if attempt == 1:
                time.sleep(2)
    raise last


def fetch_certspotter(domain, key=""):
    """SSLMate Cert Spotter API, following pagination. Small free quota without a key."""
    headers = {"Authorization": f"Bearer {key}"} if key else None
    names, after = [], ""
    for _ in range(50):
        url = ("https://api.certspotter.com/v1/issuances?domain=" + urllib.parse.quote(domain)
               + "&include_subdomains=true&expand=dns_names")
        if after:
            url += "&after=" + urllib.parse.quote(after)
        try:
            rows = get_json("certspotter", url, headers)
        except RuntimeError:
            if names:
                return names  # keep what was read before the quota ran out
            raise
        if not rows:
            break
        for r in rows:
            names += r.get("dns_names", [])
        after = rows[-1]["id"]
    return names


def fetch_hackertarget(domain, key=""):
    """HackerTarget host search: plain text 'host,ip' lines. 50 requests/day without a key."""
    url = "https://api.hackertarget.com/hostsearch/?q=" + urllib.parse.quote(domain)
    if key:
        url += "&apikey=" + urllib.parse.quote(key)
    try:
        status, body = _get(url, 60)
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(f"hackertarget: {exc}")
    text = body.decode(errors="replace").strip()
    if status != 200 or text.startswith("error") or "API count exceeded" in text:
        raise RuntimeError(f"hackertarget: {text[:150]}")
    return [line.split(",", 1)[0] for line in text.splitlines()]


def fetch_urlscan(domain, key=""):
    """urlscan.io search for pages on the domain, following pagination."""
    headers = {"API-Key": key} if key else None
    size = 1000 if key else 100
    names, after = [], ""
    for _ in range(5):
        url = f"https://urlscan.io/api/v1/search/?q={urllib.parse.quote('domain:' + domain)}&size={size}"
        if after:
            url += "&search_after=" + urllib.parse.quote(after)
        res = get_json("urlscan", url, headers)
        results = res.get("results", [])
        for r in results:
            names += [r.get("page", {}).get("domain", ""), r.get("task", {}).get("domain", "")]
        if not res.get("has_more") or not results:
            break
        after = ",".join(str(v) for v in results[-1].get("sort", []))
    return names


def fetch_wayback(domain, key=""):
    """Hostnames of the URLs archived by the Wayback Machine. Slow: capped at 6000 URLs,
    so the result is partial on large domains."""
    url = ("https://web.archive.org/cdx/search/cdx?url=" + urllib.parse.quote(domain)
           + "&matchType=domain&fl=original&collapse=urlkey&output=json&limit=6000")
    rows = get_json("wayback", url, timeout=60)
    return [url_host(r[0]) for r in rows[1:] if r]  # first row is the header


def url_host(raw):
    """Host of a possibly malformed archived URL."""
    raw = raw.split("://", 1)[-1]
    raw = re.split(r"[/?#]", raw, maxsplit=1)[0].rsplit("@", 1)[-1]
    if raw.startswith("["):
        return raw[1:].split("]", 1)[0]
    return raw.split(":", 1)[0]


def fetch_virustotal(domain, key=""):
    """Subdomains known to VirusTotal. Free API: 4 requests/minute, so pages are spaced."""
    _require("virustotal", key)
    names = []
    url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}/subdomains?limit=40"
    for page in range(4):
        if not url:
            break
        if page:
            time.sleep(16)
        res = get_json("virustotal", url, {"x-apikey": key})
        names += [d.get("id", "") for d in res.get("data", [])]
        url = res.get("links", {}).get("next", "")
    return names


def fetch_domscan(domain, key=""):
    """DomScan subdomain finder. Each page costs 4-5 of the 1,000 free monthly credits, so at most
    3 pages of 500 names are read. A 202 answer means the lookup is still running: retried."""
    _require("domscan", key)
    names, cursor = [], ""
    for _ in range(3):
        url = "https://domscan.net/v1/subdomains?limit=500&domain=" + urllib.parse.quote(domain)
        if cursor:
            url += "&cursor=" + urllib.parse.quote(cursor)
        for attempt in range(4):
            try:
                status, body = _get(url, 60, {"X-API-Key": key})
            except (OSError, urllib.error.URLError) as exc:
                raise RuntimeError(f"domscan: {exc}")
            if status != 202:
                break
            time.sleep(5)
        if status == 402:
            raise RuntimeError("domscan: plus de crédits ce mois-ci (1 000 gratuits/mois)")
        if status == 202:
            raise RuntimeError("domscan: lookup still running, try again in a minute")
        if status in (401, 403):
            raise RuntimeError(f"domscan: key refused (HTTP {status})")
        if status == 429:
            raise RuntimeError("domscan: rate limit reached")
        if status != 200:
            raise RuntimeError(f"domscan: HTTP {status}: {body[:150].decode(errors='replace').strip()}")
        res = json.loads(body)
        names += [s.get("name", "") for s in res.get("subdomains", [])]
        cursor = res.get("next_cursor") or ""
        if not res.get("has_more") or not cursor:
            break
    return names


def fetch_viewdns(domain, key=""):
    """ViewDNS subdomain discovery API (1,000 names per page, one query each). At most 2 pages
    are read so the trial quota lasts."""
    _require("viewdns", key)
    names = []
    for page in (1, 2):
        url = (f"https://api.viewdns.info/subdomains/?output=json&page={page}"
               f"&domain={urllib.parse.quote(domain)}&apikey={urllib.parse.quote(key)}")
        res = get_json("viewdns", url).get("response", {})
        if res.get("error"):
            raise RuntimeError(f"viewdns: {res['error']}")
        names += [s.get("name", "") for s in res.get("subdomains", [])]
        if page >= int(res.get("total_pages") or 1):
            break
    return names


def fetch_shodan_dns(domain, key=""):
    """Subdomains Shodan knows for the domain (key required, 1 query credit). Labels, "" = the domain."""
    _require("shodan", key)
    res = get_json("shodan", f"https://api.shodan.io/dns/domain/{urllib.parse.quote(domain)}?key={urllib.parse.quote(key)}")
    return [domain] + [f"{s}.{domain}" for s in res.get("subdomains", []) if s]


# DNS brute force: the most common subdomain labels, resolved through the system resolver.
# Active test (one DNS query per word): only on domains you are allowed to test.
WORDLIST_FILE = ASSETS / "subdomains.txt"
custom_wordlist = []  # replaces the built-in list when --wordlist is given


def wordlist_words():
    lines = custom_wordlist or WORDLIST_FILE.read_text(encoding="utf-8").splitlines()
    return list(dict.fromkeys(w.strip().strip(".").lower() for w in lines
                              if w.strip() and not w.strip().startswith("#")))


def _lookup_ips(name):
    try:
        return {i[4][0].split("%")[0] for i in socket.getaddrinfo(name, None)}
    except (socket.gaierror, UnicodeError, OSError):
        return set()


def fetch_wordlist(domain, key=""):
    """Resolve every label of the list, 64 at a time. Two random names are resolved first: if they
    answer, the zone has a wildcard and names pointing only to those addresses are dropped."""
    wild = set()
    for _ in range(2):
        wild |= _lookup_ips(f"nx-{os.urandom(8).hex()}.{domain}")
    names = [f"{w}.{domain}" for w in wordlist_words()]
    with ThreadPoolExecutor(max_workers=64) as pool:
        resolved = list(pool.map(_lookup_ips, names))
    return [n for n, ips in zip(names, resolved) if ips and not (wild and ips <= wild)]


def fetch_dnsdumpster(domain, key=""):
    """DNS records found by DNSDumpster: every 'host' field of the answer is taken."""
    _require("dnsdumpster", key)
    res = get_json("dnsdumpster", f"https://api.dnsdumpster.com/domain/{urllib.parse.quote(domain)}",
                   {"X-API-Key": key})
    names = []

    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                if k == "host" and isinstance(x, str):
                    names.append(x)
                else:
                    walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(res)
    return names


# key: "" = no key, "optional" or "required". default: queried when no source is chosen.
SUB_SOURCES = [
    {"name": "crtname", "label": "crt.name", "key": "", "default": True, "slow": False,
     "help": "Index CT le plus complet. 100 requêtes/jour/IP", "fetch": fetch_crt_name},
    {"name": "certspotter", "label": "Cert Spotter", "key": "optional", "default": True, "slow": False,
     "help": "Logs CT. Petit quota sans clé", "fetch": fetch_certspotter},
    {"name": "hackertarget", "label": "HackerTarget", "key": "optional", "default": True, "slow": False,
     "help": "DNS passif. 50 requêtes/jour sans clé", "fetch": fetch_hackertarget},
    {"name": "urlscan", "label": "urlscan.io", "key": "optional", "default": True, "slow": False,
     "help": "Sites scannés par urlscan", "fetch": fetch_urlscan},
    {"name": "virustotal", "label": "VirusTotal", "key": "required", "default": True, "slow": False,
     "help": "DNS passif. 4 requêtes/minute", "fetch": fetch_virustotal},
    {"name": "dnsdumpster", "label": "DNSDumpster", "key": "required", "default": True, "slow": False,
     "help": "Enregistrements DNS", "fetch": fetch_dnsdumpster},
    {"name": "domscan", "label": "DomScan", "key": "required", "default": True, "slow": False,
     "help": "Logs CT. 1 000 crédits/mois gratuits (4-5 par page)", "fetch": fetch_domscan},
    {"name": "viewdns", "label": "ViewDNS", "key": "required", "default": True, "slow": False,
     "help": "Index ViewDNS. 250 requêtes d'essai puis payant (1 par page)", "fetch": fetch_viewdns},
    {"name": "shodan", "label": "Shodan", "key": "required", "default": True, "slow": False,
     "help": "Noms vus par les scans Shodan. 1 crédit de requête par domaine", "fetch": fetch_shodan_dns},
    {"name": "wordlist", "label": "Dictionnaire DNS", "key": "", "default": False, "slow": False,
     "help": "Force brute DNS : 1 000 noms courants (ou --wordlist), avec détection des wildcards",
     "fetch": fetch_wordlist},
    {"name": "crtsh", "label": "crt.sh", "key": "", "default": False, "slow": True,
     "help": "Logs CT. Souvent lent ou surchargé", "fetch": fetch_crt_sh},
    {"name": "wayback", "label": "Wayback Machine", "key": "", "default": False, "slow": True,
     "help": "URL archivées : anciens noms. Lent", "fetch": fetch_wayback},
]
SOURCES_BY_NAME = {s["name"]: s for s in SUB_SOURCES}


def usable(source, keys):
    return source["key"] != "required" or bool(keys.get(source["name"]))


def resolve_source_names(items, keys):
    """'default', 'all' or a list of names -> source names. Keyed sources without key are skipped."""
    out = []
    for item in items:
        item = item.strip()
        if item == "default":
            names = [s["name"] for s in SUB_SOURCES if s["default"] and usable(s, keys)]
        elif item == "all":
            names = [s["name"] for s in SUB_SOURCES if usable(s, keys)]
        else:
            names = [item] if item else []
        out += [n for n in names if n not in out]
    return out


def normalize_domain(d):
    """'https://*.Example.com/' -> 'example.com'."""
    d = d.strip().lower()
    if "://" in d:
        d = urllib.parse.urlparse(d).hostname or ""
    if d.startswith("*."):
        d = d[2:]
    return d.strip("./")


def clean_name(name, domain):
    """Keep a name only if it is a plain hostname under domain."""
    name = name.strip().lower()
    if name.startswith("*."):
        name = name[2:]
    name = name.rstrip(".")
    if not name or any(c in name for c in " @*/:"):
        return None
    if name != domain and not name.endswith("." + domain):
        return None
    return name


def is_internal_ip(ip):
    ip = ipaddress.ip_address(ip)
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _resolves(name, private_only):
    try:
        infos = socket.getaddrinfo(name, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    return any(not private_only or is_internal_ip(i[4][0].split("%")[0]) for i in infos)


def ct_lookup(domains, sources=None, keys=None, resolve=True, private_only=False, log=print):
    """Unique hostnames found by the passive sources. Sources run in parallel."""
    keys = keys if keys is not None else load_keys()
    sources = [s.strip() for s in (sources or resolve_source_names(["default"], keys)) if s.strip()]
    found = set()
    for raw in domains:
        domain = normalize_domain(raw)
        if not domain:
            continue
        known = [s for s in sources if s in SOURCES_BY_NAME]
        for s in sources:
            if s not in SOURCES_BY_NAME:
                log(f"[src] unknown source {s!r} (available: {', '.join(SOURCES_BY_NAME)})")
        for s in known:
            log(f"[src] {domain}: querying {s}...")

        def run(name, domain=domain):
            start = time.monotonic()
            try:
                return name, SOURCES_BY_NAME[name]["fetch"](domain, keys.get(name, "")), "", time.monotonic() - start
            except Exception as exc:  # network errors, bad JSON, quota...
                return name, [], str(exc), time.monotonic() - start

        with ThreadPoolExecutor(max_workers=max(1, len(known))) as pool:
            for name, names, err, elapsed in pool.map(run, known):
                mine = {h for h in (clean_name(n, domain) for n in names) if h}
                new = mine - found
                found |= mine
                if err:
                    log(f"[src] {domain}: {err}")
                log(f"[src] {domain}: {name} -> {len(mine)} names ({len(new)} new) in {elapsed:.0f} s")

    names = sorted(found)
    if resolve or private_only:
        with ThreadPoolExecutor(max_workers=32) as pool:
            keep = list(pool.map(lambda n: _resolves(n, private_only), names))
        before = len(names)
        names = [n for n, k in zip(names, keep) if k]
        what = "resolve to a private IP" if private_only else "resolve in DNS"
        log(f"[src] {len(names)}/{before} names {what}")
    return names


# --- AS prefixes (RIPEstat) ----------------------------------------------------------

ASN_RE = re.compile(r"^AS(\d+)$", re.IGNORECASE)


def ripe_prefixes(asn):
    res = get_json("ripestat", f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}")
    out = []
    for p in res.get("data", {}).get("prefixes", []):
        try:
            if ipaddress.ip_network(p["prefix"]).version == 4:
                out.append(p["prefix"])
        except (KeyError, ValueError):
            pass
    return out


def expand_asns(items, log=print):
    """Replace 'AS1234' items with the IPv4 prefixes the AS announces."""
    out = []
    for raw in items:
        m = ASN_RE.match(raw.split("#", 1)[0].strip())
        if not m:
            out.append(raw)
            continue
        try:
            prefixes = ripe_prefixes(m.group(1))
            log(f"[asn] AS{m.group(1)}: {len(prefixes)} IPv4 prefixes announced")
            out += prefixes
        except RuntimeError as exc:
            log(f"[asn] AS{m.group(1)}: {exc}")
    return out


# --- CSV import (AD, ADCS, CMDB) ------------------------------------------------------
# Strong hints are all read together (Common Name and SAN of a certificate export);
# weak hints are used only when no strong one matches.
HOST_COLUMN_HINTS = [
    ["dnshostname", "hostname", "fqdn", "commonname", "dnsname", "subjectalternativename", "san",
     "ipv4address", "ipaddress"],
    ["ip", "host", "name", "address"],
]
HOST_TOKEN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}\b"
                        r"|\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b", re.IGNORECASE)


def looks_like_csv(lines):
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            # A comma in a trailing comment ("10.0.0.1  # web, prod") does not make a CSV
            line = line.split("#", 1)[0]
            return "," in line or ";" in line
    return False


def targets_from_csv(lines):
    """Hosts and IPs from a CSV export (columns that look like host fields, else every cell)."""
    # Comment or blank lines before the header would hide the header and its delimiter
    lines = list(lines)
    while lines and (not lines[0].strip() or lines[0].strip().startswith("#")):
        lines.pop(0)
    if not lines:
        return []
    delim = ";" if lines[0].count(";") > lines[0].count(",") else ","
    rows = list(csv.reader(io.StringIO("\n".join(lines)), delimiter=delim))
    if not rows:
        return []
    norm = [re.sub(r'[\s_\-"\ufeff]', "", h.lower()) for h in rows[0]]
    cols = []
    for tier in HOST_COLUMN_HINTS:
        cols = [i for i, h in enumerate(norm) if any(hint in h for hint in tier)]
        if cols:
            break  # DNSHostName wins over Name
    # With host columns, the first row is their header. Without, there may be no header at all
    # ("10.0.0.1,10.0.0.2"): every row is scanned, a real header holds no host token anyway.
    out = []
    for row in (rows[1:] if cols else rows):
        for i, cell in enumerate(row):
            if not cols or i in cols:
                out += [t.lower() for t in HOST_TOKEN.findall(cell)]
    return out


def import_targets(lines):
    """Plain list (one target per line) or CSV export."""
    return targets_from_csv(lines) if looks_like_csv(lines) else lines
