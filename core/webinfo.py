"""
core/webinfo.py - What a captured web page reveals, without any extra scan.

- technologies and versions (server headers, cookies, meta generator, scripts, HTML markers),
  then the CVEs of the versions found (NVD), ranked with CISA KEV and FIRST EPSS
- favicon hash (MurmurHash3, same value as Shodan's http.favicon.hash)
- sensitive pages: directory listing ("Index of /"), login form, admin panel, default page,
  debug or error page
- grouping of visually identical captures (perceptual hash of the screenshot)
- security headers and cookie flags

Everything comes from the page already loaded for the screenshot; the only extra request is the
favicon. Only product names and versions are sent to NVD, never an address or a host name.
"""

import codecs
import csv
import html
import re
import time
import urllib.parse

from .sources import get_json

# --- Technology fingerprints -----------------------------------------------------------
# Each rule: name, CPE vendor:product list (for the CVE lookup, "*" = any vendor), admin panel
# or not, and patterns. The first capture group of a pattern, when present, is the version.
# Pattern places: header:<name> (value), title, html (rendered DOM), generator (meta),
# script (src of a script), cookie (name of a cookie set by the page).

V = r"(\d+(?:\.\d+)+[a-z]?)"  # version: 2.4.59, 1.1.1f

RULES = [
    ("Apache httpd", ["apache:http_server"], False, [("header:server", rf"\bApache(?![-\w])(?:/{V})?")]),
    ("nginx", ["f5:nginx", "nginx:nginx"], False, [("header:server", rf"\bnginx(?:/{V})?")]),
    ("Microsoft IIS", ["microsoft:internet_information_services"], False,
     [("header:server", rf"Microsoft-IIS(?:/{V})?")]),
    ("Microsoft HTTPAPI", [], False, [("header:server", rf"Microsoft-HTTPAPI(?:/{V})?")]),
    ("OpenResty", ["openresty:openresty"], False, [("header:server", rf"openresty(?:/{V})?")]),
    ("LiteSpeed", ["litespeedtech:litespeed_web_server"], False, [("header:server", r"LiteSpeed")]),
    ("lighttpd", ["lighttpd:lighttpd"], False, [("header:server", rf"lighttpd(?:/{V})?")]),
    ("Caddy", [], False, [("header:server", r"\bCaddy\b")]),
    ("Envoy", [], False, [("header:server", r"\benvoy\b")]),
    ("Kestrel", [], False, [("header:server", r"\bKestrel\b")]),
    ("Squid", ["squid-cache:squid"], False, [("header:server", rf"squid(?:/{V})?"), ("header:via", rf"squid(?:/{V})?")]),
    ("Varnish", [], False, [("header:x-varnish", r"."), ("header:via", r"varnish")]),
    ("OpenSSL", ["openssl:openssl"], False, [("header:server", rf"OpenSSL/{V}")]),
    ("PHP", ["php:php"], False, [("header:x-powered-by", rf"PHP(?:/{V})?"), ("header:server", rf"PHP/{V}"),
                                 ("cookie", r"^PHPSESSID$")]),
    ("Python", ["python:python"], False, [("header:server", rf"\bPython/{V}")]),
    ("Werkzeug", ["palletsprojects:werkzeug"], False, [("header:server", rf"Werkzeug(?:/{V})?")]),
    ("gunicorn", ["gunicorn:gunicorn"], False, [("header:server", rf"gunicorn(?:/{V})?")]),
    ("Express", [], False, [("header:x-powered-by", r"^Express$")]),
    ("ASP.NET", [], False, [("header:x-powered-by", r"ASP\.NET"), ("header:x-aspnet-version", V),
                            ("cookie", r"^ASP\.NET_SessionId$")]),
    ("Java servlet", [], False, [("cookie", r"^JSESSIONID$")]),
    ("Apache Tomcat", ["apache:tomcat"], False, [("title", rf"Apache Tomcat(?:/{V})?"),
                                                  ("html", rf"<h3>Apache Tomcat/{V}</h3>"),
                                                  ("header:server", r"Apache-Coyote")]),
    ("Jetty", ["eclipse:jetty"], False, [("header:server", rf"Jetty\((?:{V})?")]),
    ("Spring Boot", [], False, [("html", r"Whitelabel Error Page")]),
    ("WordPress", ["wordpress:wordpress"], False, [("generator", rf"WordPress\s*{V}?"),
                                                   ("html", r"/wp-(?:content|includes)/")]),
    ("Drupal", ["drupal:drupal"], False, [("generator", r"Drupal\s*(\d+)?"),
                                          ("header:x-generator", r"Drupal\s*(\d+)?")]),
    ("Joomla", [], False, [("generator", r"Joomla")]),
    ("Grafana", ["grafana:grafana"], True, [("title", r"^Grafana\b"),
                                            ("html", rf'"buildInfo":\{{[^}}]*?"version":"{V}')]),
    ("Kibana", ["elastic:kibana"], True, [("header:kbn-version", V), ("header:kbn-name", r".")]),
    ("Jenkins", ["jenkins:jenkins"], True, [("header:x-jenkins", V)]),
    ("GitLab", ["gitlab:gitlab"], True, [("generator", r"GitLab"), ("html", r'content="GitLab"')]),
    ("phpMyAdmin", ["phpmyadmin:phpmyadmin"], True, [("title", r"phpMyAdmin")]),
    ("Webmin", ["webmin:webmin"], True, [("header:server", rf"MiniServ(?:/{V})?")]),
    ("Confluence", ["atlassian:confluence_server", "atlassian:confluence_data_center"], False,
     [("header:x-confluence-request-time", r"."), ("html", rf'name="ajs-version-number" content="{V}"')]),
    ("Jira", [], False, [("html", r'name="application-name" content="JIRA"')]),
    ("SonarQube", [], True, [("title", r"SonarQube")]),
    ("Nexus Repository", [], True, [("header:server", rf"Nexus(?:/{V})?")]),
    ("RabbitMQ", [], True, [("title", r"RabbitMQ Management")]),
    ("Portainer", [], True, [("title", r"^Portainer")]),
    ("Prometheus", [], True, [("title", r"Prometheus Time Series")]),
    ("Keycloak", [], False, [("html", r"/auth/resources/[^\"']+/keycloak|kc-form-login")]),
    ("Outlook Web App", [], False, [("html", r"/owa/auth/"), ("header:x-owa-version", V)]),
    ("SharePoint", [], False, [("header:microsoftsharepointteamservices", V)]),
    ("Roundcube", [], False, [("html", r"rcmloginuser|roundcube_sessid"), ("cookie", r"^roundcube_sessid$")]),
    ("Nextcloud", [], False, [("html", r"nextcloud"), ("header:x-nextcloud-well-known", r".")]),
    ("Zimbra", [], False, [("cookie", r"^ZM_TEST$"), ("title", r"Zimbra")]),
    ("Fortinet FortiGate", [], True, [("html", r"/remote/login|fgt_lang|ftnt-fortinet"),
                                       ("cookie", r"^SVPNCOOKIE$")]),
    ("Citrix NetScaler", [], True, [("cookie", r"^NSC_"), ("html", r"/vpn/index\.html|/logon/LogonPoint/")]),
    ("Ivanti / Pulse Secure", [], True, [("html", r"/dana-na/|/dana/")]),
    ("F5 BIG-IP", [], True, [("cookie", r"^BIGipServer"), ("header:server", r"BigIP"),
                             ("html", r"/tmui/")]),
    ("Palo Alto GlobalProtect", [], True, [("html", r"global-protect|/global-protect/")]),
    ("Cloudflare", [], False, [("header:server", r"^cloudflare$"), ("header:cf-ray", r".")]),
    ("Akamai", [], False, [("header:server", r"AkamaiGHost")]),
    ("jQuery", ["jquery:jquery"], False, [("script", rf"jquery[.-]{V}(?:\.slim)?(?:\.min)?\.js")]),
    ("Bootstrap", ["getbootstrap:bootstrap"], False, [("script", rf"bootstrap[@/.-]{V}")]),
    ("Angular", [], False, [("html", rf'ng-version="{V}"')]),
    ("React", [], False, [("html", r"data-reactroot|__NEXT_DATA__")]),
    ("Vue.js", [], False, [("html", r"data-v-[0-9a-f]{8}")]),
]
_COMPILED = [(name, cpes, admin, [(where, re.compile(rx, re.I)) for where, rx in pats])
             for name, cpes, admin, pats in RULES]

_SCRIPT_RX = re.compile(r"<script[^>]+src=[\"']([^\"']+)", re.I)
_GEN_RX = re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)|"
                     r"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+name=[\"']generator[\"']", re.I)


def header_map(headers):
    """[{name, value}] -> {lowercase name: values joined by newline}."""
    out = {}
    for h in headers or []:
        n = h["name"].lower()
        out[n] = f"{out[n]}\n{h['value']}" if n in out else h["value"]
    return out


def cookie_list(headers):
    """Set-Cookie headers -> [(name, lowercase attributes)]."""
    out = []
    for h in headers or []:
        if h["name"].lower() == "set-cookie":
            for line in h["value"].split("\n"):
                first, _, attrs = line.partition(";")
                name = first.split("=", 1)[0].strip()
                if name:
                    out.append((name, attrs.lower()))
    return out


def detect_tech(headers, page_html, title):
    """-> [{"name", "version", "cpes", "admin"}], one entry per technology."""
    hmap = header_map(headers)
    cookies = [n for n, _ in cookie_list(headers)]
    scripts = _SCRIPT_RX.findall(page_html or "")
    gens = [a or b for a, b in _GEN_RX.findall(page_html or "")]
    found = []
    for name, cpes, admin, pats in _COMPILED:
        hit, version = False, ""
        for where, rx in pats:
            if where.startswith("header:"):
                texts = [hmap.get(where[7:], "")]
            elif where == "title":
                texts = [title or ""]
            elif where == "html":
                texts = [page_html or ""]
            elif where == "generator":
                texts = gens
            elif where == "script":
                texts = scripts
            else:  # cookie
                texts = cookies
            for t in texts:
                m = rx.search(t) if t else None
                if m:
                    hit = True
                    if not version and m.groups() and m.group(1):
                        version = m.group(1)
        if hit:
            found.append({"name": name, "version": version, "cpes": cpes, "admin": admin})
    return found


def tech_label(t):
    return f"{t['name']} {t['version']}".strip()


# --- Sensitive pages --------------------------------------------------------------------

TAGS = {  # tag -> label shown in the report
    "index-of": "Index of (liste de fichiers)",
    "debug": "page de debug / erreur détaillée",
    "default": "page par défaut",
    "admin": "interface d'administration",
    "login": "formulaire de connexion",
    "auth-http": "authentification HTTP",
}
_INDEX_TITLE = re.compile(r"^\s*(Index of /|Directory listing for /|Listing of /)", re.I)
_INDEX_HTML = re.compile(r"<h1>\s*Index of /|\?C=N;O=D|\[To Parent Directory\]|<title>[^<]* - /</title>", re.I)
_DEFAULT = re.compile(
    r"Apache2 (?:Ubuntu|Debian) Default Page|Test Page for the (?:Apache|Nginx) HTTP Server|"
    r"<h1>It works!</h1>|Welcome to nginx!|Welcome to OpenResty!|IIS Windows Server|"
    r"<title>IIS\d*</title>|Internet Information Services|Welcome to CentOS|Welcome to JBoss|"
    r"Caddy works!|Default Web Site Page|Web Server's Default Page|Plesk Obsidian|"
    r"If you're seeing this, you've successfully installed Tomcat", re.I)
_DEBUG = re.compile(
    r"Traceback \(most recent call last\)|Werkzeug Debugger|You're seeing this error because you have "
    r"<code>DEBUG = True|Whitelabel Error Page|<title>phpinfo\(\)</title>|Fatal error</b>:|"
    r"Stack Trace:|Server Error in '/' Application|Laravel</title>|Symfony Exception", re.I)
_ADMIN_TXT = re.compile(r"\b(admin|administration|administrator|manager|management|console|dashboard|"
                        r"backoffice|back-office|webmin|cpanel|plesk|phpmyadmin|portainer|router|firewall)\b", re.I)
_LOGIN_TXT = re.compile(r"\b(log ?in|sign ?in|connexion|se connecter|authentification|authentication|"
                        r"identification|logon)\b", re.I)
_PASSWORD = re.compile(r"<input[^>]+type=[\"']?password", re.I)


def page_tags(title, page_html, final_url, status, headers, tech):
    """Sensitive page markers, most important first."""
    title = title or ""
    page_html = page_html or ""
    tags = []
    if _INDEX_TITLE.search(title) or _INDEX_HTML.search(page_html):
        tags.append("index-of")
    if _DEBUG.search(page_html):
        tags.append("debug")
    if _DEFAULT.search(title) or _DEFAULT.search(page_html[:20000]):
        tags.append("default")
    path = urllib.parse.urlsplit(final_url or "").path
    if any(t["admin"] for t in tech) or _ADMIN_TXT.search(title) or _ADMIN_TXT.search(path):
        tags.append("admin")
    if _PASSWORD.search(page_html) or _LOGIN_TXT.search(title):
        tags.append("login")
    if str(status) == "401" or "www-authenticate" in header_map(headers):
        tags.append("auth-http")
    return tags


def is_index_page(page_html):
    """Directory listing page (Apache, nginx, lighttpd, IIS, Python http.server...)."""
    page_html = page_html or ""
    m = re.search(r"<title>([^<]*)</title>", page_html, re.I)
    return bool((m and _INDEX_TITLE.search(m.group(1))) or _INDEX_HTML.search(page_html))


# --- Common folders (--dirs) ----------------------------------------------------------------
# Optional, off by default: one light HTTP request per folder of assets/dirs.txt on every web
# service found. Only answers that are a directory listing are kept (and then captured).

DIRS_PARALLEL = 6


def dir_words(custom=None):
    """Folders to test: custom list or assets/dirs.txt, each ending with '/'."""
    from . import ASSETS
    lines = custom or (ASSETS / "dirs.txt").read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines:
        w = line.split("#", 1)[0].strip().strip("/") if not line.lstrip().startswith("#") else ""
        if w and w + "/" not in out:
            out.append(w + "/")
    return out


async def probe_dirs(context, base_url, words, timeout_s, limiter=None, stop=None):
    """Request base_url + each folder; return the URLs that answer with a directory listing."""
    import asyncio
    sem = asyncio.Semaphore(DIRS_PARALLEL)
    found = []

    async def one(word):
        url = urllib.parse.urljoin(base_url, word)
        async with sem:
            if stop and stop.is_set():
                return
            if limiter:
                await limiter.wait(stop)
            try:
                resp = await context.request.get(url, timeout=timeout_s * 1000, max_redirects=2)
                if resp.status == 200 and "html" in resp.headers.get("content-type", "html").lower():
                    body = (await resp.body())[:200000].decode("utf-8", "replace")
                    if is_index_page(body):
                        found.append(url)
            except Exception:
                pass

    await asyncio.gather(*(one(w) for w in words))
    return sorted(found)


# --- Security headers -------------------------------------------------------------------

def header_issues(final_url, headers, page_html):
    """Missing security headers, disclosed versions, weak cookies. -> [str]"""
    hmap = header_map(headers)
    https = (final_url or "").lower().startswith("https://")
    out = []
    csp = hmap.get("content-security-policy", "")
    if https and "strict-transport-security" not in hmap:
        out.append("HSTS absent")
    if not csp:
        out.append("CSP absente")
    if "x-frame-options" not in hmap and "frame-ancestors" not in csp.lower():
        out.append("anti-clickjacking absent (X-Frame-Options / frame-ancestors)")
    if hmap.get("x-content-type-options", "").strip().lower() != "nosniff":
        out.append("X-Content-Type-Options: nosniff absent")
    if "referrer-policy" not in hmap:
        out.append("Referrer-Policy absente")
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        v = hmap.get(h, "")
        if v and (h != "server" or re.search(r"\d", v)):
            out.append(f"version divulguée ({h}: {v[:60]})")
    if not https and _PASSWORD.search(page_html or ""):
        out.append("mot de passe saisi en HTTP clair")
    for name, attrs in cookie_list(headers):
        missing = [flag for flag, ok in (("Secure", "secure" in attrs or not https),
                                         ("HttpOnly", "httponly" in attrs),
                                         ("SameSite", "samesite" in attrs)) if not ok]
        if missing:
            out.append(f"cookie {name} sans {', '.join(missing)}")
    return out


# --- Favicon hash -----------------------------------------------------------------------

def mmh3_32(data, seed=0):
    """MurmurHash3 x86 32 bits, signed (same as the mmh3 Python package)."""
    m = 0xFFFFFFFF
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed & m
    n = len(data)
    end = n - n % 4
    for i in range(0, end, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & m
        k = ((k << 15) | (k >> 17)) & m
        h ^= (k * c2) & m
        h = ((h << 13) | (h >> 19)) & m
        h = (h * 5 + 0xE6546B64) & m
    k = 0
    tail = data[end:]
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if tail:
        k ^= tail[0]
        k = (k * c1) & m
        k = ((k << 15) | (k >> 17)) & m
        h ^= (k * c2) & m
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & m
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & m
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


def favicon_hash(data):
    """Shodan http.favicon.hash: MurmurHash3 of the base64 text with a newline every 76 characters."""
    return mmh3_32(codecs.encode(data, "base64"))


def shodan_favicon_url(h):
    return "https://www.shodan.io/search?query=" + urllib.parse.quote(f"http.favicon.hash:{h}")


FAVICON_JS = """() => {
  const l = document.querySelector('link[rel~="icon" i], link[rel="shortcut icon" i], link[rel="apple-touch-icon" i]');
  return l && l.href ? l.href : new URL('/favicon.ico', location.href).href;
}"""


async def fetch_favicon(page, context, timeout_s, cache):
    """Favicon of the loaded page -> (url, hash) or ("", ""). One download per favicon URL."""
    try:
        url = await page.evaluate(FAVICON_JS)
    except Exception:
        return "", ""
    if not url.lower().startswith(("http://", "https://")):
        return "", ""  # data: URI or nothing usable
    if url in cache:
        return url, cache[url]
    value = ""
    try:
        resp = await context.request.get(url, timeout=timeout_s * 1000, max_redirects=3)
        body = await resp.body()
        ctype = resp.headers.get("content-type", "").lower()
        # Many servers answer a missing favicon with their HTML page: not an icon
        head = body.lstrip()[:5].lower()
        svg = ctype.startswith("image/svg") or head.startswith((b"<svg", b"<?xml"))
        if resp.ok and body and "html" not in ctype and (svg or not head.startswith(b"<")):
            value = favicon_hash(body)
    except Exception:
        pass
    cache[url] = value
    return url, value


# --- Visual grouping --------------------------------------------------------------------
# Difference hash of the screenshot, computed in a blank page of the browser (no image
# library needed). The bottom 40 px are left out: that is where the banner with the date is.

PHASH_JS = """async (b64) => {
  const bin = atob(b64);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  const bmp = await createImageBitmap(new Blob([u], {type: 'image/png'}));
  const h = Math.max(1, bmp.height - 40);
  const mid = new OffscreenCanvas(68, 64);
  const m = mid.getContext('2d');
  m.imageSmoothingQuality = 'high';
  m.drawImage(bmp, 0, 0, bmp.width, h, 0, 0, 68, 64);
  const c = new OffscreenCanvas(17, 16);
  const x = c.getContext('2d');
  x.imageSmoothingQuality = 'high';
  x.drawImage(mid, 0, 0, 17, 16);
  const d = x.getImageData(0, 0, 17, 16).data;
  let bits = '';
  for (let y = 0; y < 16; y++) for (let i = 0; i < 16; i++) {
    const p = (y * 17 + i) * 4, q = p + 4;
    bits += (d[p] * 299 + d[p + 1] * 587 + d[p + 2] * 114) > (d[q] * 299 + d[q + 1] * 587 + d[q + 2] * 114) ? '1' : '0';
  }
  return BigInt('0b' + bits).toString(16).padStart(64, '0');
}"""
PHASH_MAX_DISTANCE = 20  # bits out of 256


async def screenshot_phash(hasher_page, png_bytes):
    import base64
    try:
        return await hasher_page.evaluate(PHASH_JS, base64.b64encode(png_bytes).decode())
    except Exception:
        return ""


def group_similar(results, max_distance=PHASH_MAX_DISTANCE):
    """Set r["group"] (1, 2...) and r["group_size"] on captures that look alike; 0 when alone.
    Returns the groups, largest first: [[result, ...], ...]."""
    shots = [r for r in results if r.get("phash")]
    hashes = [int(r["phash"], 16) for r in shots]
    parent = list(range(len(shots)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(shots)):
        for j in range(i + 1, len(shots)):
            if (hashes[i] ^ hashes[j]).bit_count() <= max_distance:
                parent[find(j)] = find(i)
    clusters = {}
    for i, r in enumerate(shots):
        clusters.setdefault(find(i), []).append(r)
    groups = sorted((g for g in clusters.values() if len(g) > 1), key=len, reverse=True)
    for r in results:
        r["group"], r["group_size"] = 0, 1
    for n, g in enumerate(groups, start=1):
        for r in g:
            r["group"], r["group_size"] = n, len(g)
    return groups


# --- CVEs of the versions found (NVD) ---------------------------------------------------

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _cvss(cve):
    metrics = cve.get("metrics") or {}
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(k) or []:
            score = (m.get("cvssData") or {}).get("baseScore")
            if score is not None:
                return float(score)
    return 0.0


def nvd_cves(cpe_product, version, key="", log=print):
    """CVEs whose configurations include this product version. -> {cve: cvss}"""
    match = f"cpe:2.3:a:{cpe_product}:{version}"
    out, start = {}, 0
    while True:
        url = (f"{NVD_URL}?virtualMatchString={urllib.parse.quote(match, safe=':*')}&noRejected"
               f"&resultsPerPage=2000&startIndex={start}")
        res = get_json("nvd", url, headers={"apiKey": key} if key else None, timeout=60)
        for v in res.get("vulnerabilities", []):
            c = v.get("cve") or {}
            if c.get("id"):
                out[c["id"]] = _cvss(c)
        start += res.get("resultsPerPage", 0) or 2000
        if start >= res.get("totalResults", 0):
            return out


def tech_inventory(results):
    """Distinct technologies across results -> [{"name", "version", "cpes", "urls", "vulns"}]."""
    inv = {}
    for r in results:
        for t in r.get("tech") or []:
            e = inv.setdefault((t["name"], t["version"]), {**t, "urls": [], "vulns": []})
            if r["url"] not in e["urls"]:
                e["urls"].append(r["url"])
    return sorted(inv.values(), key=lambda e: (e["name"].lower(), e["version"]))


def lookup_tech_cves(inventory, keys, log=print, stop=None):
    """Fill e["vulns"] for every versioned technology with a CPE (NVD), then rank with KEV / EPSS."""
    from .enrich import _rank_vulns
    key = (keys or {}).get("nvd", "")
    todo = [e for e in inventory if e["version"] and e["cpes"]]
    if not todo:
        return
    pause = 0.7 if key else 6.5  # NVD: 50 requests / 30 s with a key, 5 without
    log(f"[cve] {len(todo)} version(s) à chercher dans NVD{'' if key else ' (sans clé : ~7 s par requête)'}")
    first = True
    for e in todo:
        found = {}
        for cpe in e["cpes"]:
            if stop and stop.is_set():
                return
            if not first:
                time.sleep(pause)
            first = False
            try:
                found.update(nvd_cves(cpe, e["version"], key, log))
            except RuntimeError as exc:
                log(f"[cve] {tech_label(e)} : {exc}")
        e["vulns"] = [{"cve": c, "kev": False, "epss": 0.0, "cvss": s} for c, s in sorted(found.items())]
        log(f"[cve] {tech_label(e)} : {len(found)} CVE")
    _rank_vulns(todo, log)


def write_tech_csv(inventory, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["technology", "version", "cpe", "services", "urls", "cves", "kev_cves", "max_epss", "max_cvss"])
        for e in inventory:
            v = e["vulns"]
            w.writerow([e["name"], e["version"], " ".join(e["cpes"]), len(e["urls"]), " ".join(e["urls"]),
                        " ".join(x["cve"] for x in v), " ".join(x["cve"] for x in v if x["kev"]),
                        f"{max((x['epss'] for x in v), default=0):.4f}",
                        f"{max((x.get('cvss', 0) for x in v), default=0):.1f}"])


# --- HTML for report.html -------------------------------------------------------------------

WEB_CSS = """
.tag{border-radius:3px;padding:1px 6px;font-size:12px;color:#fff;background:#666;margin-right:3px}
.tag-index-of,.tag-debug{background:#b00}.tag-admin{background:#c60}.tag-login{background:#246}
.tag-default{background:#777}.tag-auth-http{background:#357}
.tech{color:#333;font-size:12px}.fav{font-size:12px;color:#555}
.hdr{font-size:12px;color:#a50}
.dupcount{background:#555;color:#fff;border-radius:3px;padding:1px 6px;font-size:12px}
.groups{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
.groups img{width:100%;display:block}
body.nodup .card.dup{display:none}body.nodup section.alldup{display:none}
"""


def tag_badges(tags):
    return "".join(f'<span class="tag tag-{t}" title="{html.escape(TAGS.get(t, t))}">{t}</span>' for t in tags)


def card_extras(r):
    """Lines added to a capture card: tags, technologies, favicon, header issues, similar pages."""
    parts = []
    if r.get("tags"):
        parts.append(tag_badges(r["tags"]))
    if r.get("group"):
        parts.append(f'<span class="dupcount" title="captures similaires">≈ groupe {r["group"]} '
                     f'({r["group_size"]})</span>')
    out = f'<br>{" ".join(parts)}' if parts else ""
    if r.get("tech"):
        out += '<br><span class="tech">' + html.escape(", ".join(tech_label(t) for t in r["tech"])) + "</span>"
    if r.get("favicon_hash") not in (None, ""):
        h = r["favicon_hash"]
        out += (f'<br><span class="fav">favicon <a href="{shodan_favicon_url(h)}" title="recherche Shodan">'
                f'{h}</a></span>')
    if r.get("header_issues"):
        issues = r["header_issues"]
        out += (f'<br><span class="hdr" title="{html.escape(chr(10).join(issues))}">'
                f'⚠ {len(issues)} en-tête(s) / cookie(s) à revoir</span>')
    return out


def _urls(urls, limit=8):
    shown = "<br>".join(f'<a href="{html.escape(u)}">{html.escape(u)}</a>' for u in urls[:limit])
    return shown + (f"<br>+{len(urls) - limit}" if len(urls) > limit else "")


def tech_section(inventory, vuln_badges, default_creds=None):
    if not inventory:
        return ""
    rows = []
    ordered = sorted(inventory, key=lambda e: (-sum(v["kev"] for v in e["vulns"]), -len(e["vulns"]),
                                               e["name"].lower()))
    for e in ordered:
        cvss = max((v.get("cvss", 0) for v in e["vulns"]), default=0)
        rows.append(f"<tr><td>{html.escape(e['name'])}</td><td>{html.escape(e['version'] or '?')}</td>"
                    f"<td>{len(e['urls'])}</td><td>{f'{cvss:.1f}' if e['vulns'] else ''}</td>"
                    f"<td>{vuln_badges(e['vulns'], 15)}</td>"
                    f"<td>{html.escape((default_creds or {}).get(e['name'], ''))}</td><td>{_urls(e['urls'], 5)}</td></tr>")
    n_cve = sum(len(e["vulns"]) for e in inventory)
    return (f"<details open><summary><b>Technologies détectées</b> - {len(inventory)}, {n_cve} CVE "
            f"(versions lues dans les en-têtes et les pages ; à confirmer)</summary><table><tr>"
            f"<th>Technologie</th><th>Version</th><th>Services</th><th>CVSS max</th><th>CVE (NVD)</th>"
            f"<th>Identifiants par défaut connus</th><th>URL</th></tr>{''.join(rows)}</table></details>")


def sensitive_section(results):
    by_tag = {}
    for r in results:
        for t in r.get("tags") or []:
            if r["url"] not in by_tag.setdefault(t, []):
                by_tag[t].append(r["url"])
    if not by_tag:
        return ""
    rows = "".join(f"<tr><td>{tag_badges([t])}</td><td>{html.escape(TAGS[t])}</td><td>{len(by_tag[t])}</td>"
                   f"<td>{_urls(by_tag[t], 30)}</td></tr>" for t in TAGS if t in by_tag)
    return (f"<details open><summary><b>Pages sensibles</b> - {sum(map(len, by_tag.values()))}</summary>"
            f"<table><tr><th>Repère</th><th>Signification</th><th>Nombre</th><th>URL</th></tr>{rows}"
            f"</table></details>")


def headers_section(results):
    rows, counts = [], {}
    seen = set()
    for r in results:
        if not r.get("header_issues") or r["url"] in seen:
            continue
        seen.add(r["url"])
        for i in r["header_issues"]:
            k = i.split(" (")[0] if i.startswith("version divulguée") else (
                "cookie sans attribut" if i.startswith("cookie ") else i)
            counts[k] = counts.get(k, 0) + 1
        rows.append(f"<tr><td>{_urls([r['url']])}</td><td>{'<br>'.join(map(html.escape, r['header_issues']))}</td></tr>")
    if not rows:
        return ""
    summary = ", ".join(f"{k} : {n}" for k, n in sorted(counts.items(), key=lambda x: -x[1]))
    return (f"<details><summary><b>En-têtes de sécurité</b> - {len(rows)} service(s) : "
            f"{html.escape(summary)}</summary><table><tr><th>URL</th><th>Constats</th></tr>"
            f"{''.join(rows)}</table></details>")


def groups_section(groups):
    if not groups:
        return ""
    cards = []
    for n, g in enumerate(groups, start=1):
        first = g[0]
        f = html.escape(first["file"])
        urls = [r["url"] + (f" ({r['ua']})" if r.get("ua") not in (None, "", "default") else "") for r in g]
        cards.append(f'<div class="card"><a href="{f}"><img src="{f}" loading="lazy"></a><div class="meta">'
                     f'<b>Groupe {n}</b> - {len(g)} captures<br><details><summary>URL</summary>'
                     f'{_urls(urls, 200)}</details></div></div>')
    n_dup = sum(len(g) - 1 for g in groups)
    return (f"<details><summary><b>Pages similaires</b> - {len(groups)} groupe(s), {n_dup} doublon(s) visuel(s)"
            f"</summary><div class=\"groups\">{''.join(cards)}</div></details>"
            f'<label><input type="checkbox" id="nodup"> masquer les {n_dup} doublons visuels '
            f"(une seule capture par groupe)</label><br>")
