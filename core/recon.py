"""
core/recon.py - Deeper reconnaissance on the services found.

- sensitive files exposed (--files, active, list in assets/files.txt, each answer checked against
  a signature so a custom 404 page is not taken for a find)
- JavaScript of the pages (scripts already downloaded by the browser, no extra request):
  API paths, internal URLs, secrets (masked in every output)
- robots.txt, sitemap.xml, security.txt (3 light requests per service)
- subdomain takeover: CNAME towards a cloud service that no longer exists (DNS + page content)
- banners of non-web services (SSH, FTP, SMTP, POP, IMAP, MySQL, Redis, RDP...)
- known default credentials of the technologies found (a list to check by hand, nothing is tried)
- port presets: web (extended web ports), services (non-web services)
"""

import asyncio
import html
import ipaddress
import random
import re
import string
import struct
import urllib.parse

# --- Port presets ---------------------------------------------------------------------------

PORT_PRESETS = {
    "web": [80, 81, 82, 88, 280, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2083, 2086, 2087, 2095,
            2096, 2480, 3000, 3001, 3128, 3333, 4000, 4001, 4002, 4100, 4243, 4443, 4567, 4711, 4712, 4848,
            4993, 5000, 5001, 5104, 5108, 5601, 5800, 5985, 6543, 7000, 7001, 7002, 7396, 7443, 7474, 8000,
            8001, 8008, 8009, 8014, 8042, 8069, 8080, 8081, 8082, 8083, 8088, 8090, 8091, 8118, 8123, 8172,
            8181, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9001, 9043, 9060,
            9080, 9090, 9091, 9200, 9443, 9800, 9981, 10000, 10443, 12443, 15672, 16080, 18091, 18092,
            20720, 28017],
    "services": [21, 22, 23, 25, 110, 143, 389, 465, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389,
                 5432, 5900, 6379, 9042, 11211, 27017],
}

# --- Default credentials (hints only, never tried) -----------------------------------------

DEFAULT_CREDS = {
    "Apache Tomcat": "manager : tomcat/tomcat, admin/admin, tomcat/s3cret",
    "Grafana": "admin/admin",
    "RabbitMQ": "guest/guest (accepté seulement depuis localhost par défaut)",
    "phpMyAdmin": "root/(vide), root/root",
    "Webmin": "root avec le mot de passe système",
    "Kibana": "elastic/changeme (anciennes versions)",
    "SonarQube": "admin/admin",
    "Nexus Repository": "admin/admin123 (anciennes versions)",
    "Jenkins": "pas de défaut : mot de passe initial dans secrets/initialAdminPassword",
    "Portainer": "compte admin créé à la première connexion : vérifier que l'assistant n'est pas ouvert",
    "Prometheus": "aucune authentification par défaut",
    "Fortinet FortiGate": "admin/(vide) (anciennes versions)",
    "Citrix NetScaler": "nsroot/nsroot",
    "F5 BIG-IP": "admin/admin, root/default",
    "Palo Alto GlobalProtect": "admin/admin (interface d'administration)",
    "GitLab": "root défini à l'installation (initial_root_password)",
    "WordPress": "pas de défaut ; énumération des comptes via /wp-json/wp/v2/users",
    "Keycloak": "admin défini à l'installation",
    "Redis": "aucune authentification par défaut",
    "MySQL": "root/(vide) sur les anciennes installations",
    "Zimbra": "pas de défaut",
    "Webmin MiniServ": "root avec le mot de passe système",
}

# --- Common helpers ----------------------------------------------------------------------------

MAX_BYTES = 65536


async def get_text(context, url, timeout_s, max_redirects=2):
    """GET through the browser context (same proxy, UA, TLS options). -> (status, ctype, text) or None.
    Only the first 64 KB are asked for (Range)."""
    try:
        resp = await context.request.get(url, timeout=timeout_s * 1000, max_redirects=max_redirects,
                                         headers={"Range": f"bytes=0-{MAX_BYTES - 1}"})
        body = (await resp.body())[:MAX_BYTES]
        return resp.status, resp.headers.get("content-type", "").lower(), body.decode("latin-1")
    except Exception:
        return None


def mask(secret):
    s = str(secret)
    return s[:4] + "…" + s[-4:] if len(s) > 12 else s[:2] + "…"


# --- Sensitive files (--files) -----------------------------------------------------------------

SEVERITY = {"critique": 0, "haute": 1, "moyenne": 2, "info": 3}


def file_rules(custom=None):
    from . import ASSETS
    lines = custom or (ASSETS / "files.txt").read_text(encoding="utf-8").splitlines()
    rules = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.rstrip("\n").split("\t")
        path = parts[0].strip().lstrip("/")
        sev = parts[1].strip().lower() if len(parts) > 1 and parts[1].strip() else "moyenne"
        sig = parts[2] if len(parts) > 2 and parts[2] else ""
        try:
            rx = re.compile(sig) if sig else None
        except re.error:
            continue
        if path:
            rules.append({"path": path, "severity": sev if sev in SEVERITY else "moyenne", "rx": rx})
    return rules


async def probe_files(context, base_url, rules, timeout_s, limiter=None, stop=None):
    """-> [{"url", "path", "severity", "size"}] for every file whose answer matches its signature."""
    rand = "".join(random.choices(string.ascii_lowercase, k=12))
    baseline = await get_text(context, urllib.parse.urljoin(base_url, f"netshot-{rand}.txt"), timeout_s)
    base_body = baseline[2] if baseline and baseline[0] in (200, 206) else None
    sem = asyncio.Semaphore(6)
    found = []

    async def one(rule):
        url = urllib.parse.urljoin(base_url, rule["path"])
        async with sem:
            if stop and stop.is_set():
                return
            if limiter:
                await limiter.wait(stop)
            res = await get_text(context, url, timeout_s, max_redirects=0)
        if not res or res[0] not in (200, 206):
            return
        status, ctype, body = res
        if rule["rx"]:
            ok = bool(rule["rx"].search(body))
        else:  # no signature: must differ from the answer to a missing file
            ok = body.strip() and (base_body is None or abs(len(body) - len(base_body)) > 64)
        if ok:
            found.append({"url": url, "path": rule["path"], "severity": rule["severity"], "size": len(body)})

    await asyncio.gather(*(one(r) for r in rules))
    return sorted(found, key=lambda f: (SEVERITY[f["severity"]], f["path"]))


# --- robots.txt, sitemap.xml, security.txt ----------------------------------------------------

async def well_known(context, base_url, timeout_s):
    """-> {"robots": [paths], "sitemaps": [urls], "sitemap_urls": n, "sitemap_sample": [...],
           "security": {"contact": [...], "expires": ...} } (empty keys left out)."""
    out = {}
    res = await get_text(context, urllib.parse.urljoin(base_url, "robots.txt"), timeout_s)
    if res and res[0] in (200, 206) and "html" not in res[1] and re.search(r"(?im)^(user-agent|disallow|allow|sitemap)\s*:", res[2]):
        paths, maps = [], []
        for line in res[2].splitlines():
            k, _, v = line.partition(":")
            k, v = k.strip().lower(), v.split("#", 1)[0].strip()
            if k in ("disallow", "allow") and v and v != "/" and v not in paths:
                paths.append(v)
            elif k == "sitemap" and v:
                maps.append(urllib.parse.urljoin(base_url, v))
        if paths:
            out["robots"] = paths[:200]
        if maps:
            out["sitemaps"] = maps[:20]
    sm_url = (out.get("sitemaps") or [urllib.parse.urljoin(base_url, "sitemap.xml")])[0]
    res = await get_text(context, sm_url, timeout_s)
    if res and res[0] in (200, 206) and "<loc>" in res[2]:
        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", res[2])
        out["sitemap_urls"] = len(locs)
        out["sitemap_sample"] = locs[:15]
    for path in (".well-known/security.txt", "security.txt"):
        res = await get_text(context, urllib.parse.urljoin(base_url, path), timeout_s)
        if res and res[0] in (200, 206) and re.search(r"(?im)^contact\s*:", res[2]):
            sec = {"url": urllib.parse.urljoin(base_url, path)}
            for line in res[2].splitlines():
                k, _, v = line.partition(":")
                k = k.strip().lower()
                if k in ("contact", "expires", "policy", "encryption", "hiring") and v.strip():
                    sec.setdefault(k, []).append(v.strip())
            out["security"] = sec
            break
    return out


# --- JavaScript analysis ------------------------------------------------------------------------

SECRET_RULES = [
    ("Clé AWS", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("Clé Google API", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("Jeton Slack", r"\bxox[abposr]-[0-9A-Za-z-]{10,}"),
    ("Webhook Slack", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
    ("Jeton GitHub", r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}"),
    ("Jeton GitLab", r"\bglpat-[A-Za-z0-9_\-]{20}\b"),
    ("Clé Stripe secrète", r"\b(sk|rk)_live_[0-9A-Za-z]{20,}"),
    ("Clé SendGrid", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("Clé Mailgun", r"\bkey-[0-9a-f]{32}\b"),
    ("Clé Twilio", r"\bSK[0-9a-f]{32}\b"),
    ("Clé privée", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("Chaîne de connexion", r"\b(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp)://[^\s\"'<>:/]+:[^\s\"'<>@/]+@[^\s\"'<>]+"),
    ("Azure SAS / clé de stockage", r"AccountKey=[A-Za-z0-9+/=]{40,}|[?&]sig=[A-Za-z0-9%+/=]{30,}"),
    ("Secret générique", r"(?i)[\"']?(api[_-]?key|api[_-]?secret|client[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-+/=!@#$%^&*.]{12,})[\"']"),
]
_SECRET_RX = [(name, re.compile(rx)) for name, rx in SECRET_RULES]
_PLACEHOLDER = re.compile(r"(?i)^(x+|\*+|your|example|changeme|placeholder|undefined|null|true|false|test)")
_ENDPOINT_RX = re.compile(r"[\"'`](/(?:api|rest|graphql|v\d+|internal|admin|private|auth|oauth|ws|services?)"
                          r"(?:/[A-Za-z0-9_\-.{}:$]*)*)(?:\?[^\"'`\s]*)?[\"'`]")
_URL_RX = re.compile(r"https?://[A-Za-z0-9._\-]+(?::\d+)?(?:/[^\s\"'`<>()\\]*)?")
_INTERNAL_HOST = re.compile(r"(?i)\.(local|lan|corp|internal|intra|intranet|priv|home|localdomain|ad)$")
_INLINE_RX = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)
JS_MAX_FILES = 40
JS_MAX_BYTES = 3_000_000


def _is_internal_url(u):
    host = (urllib.parse.urlsplit(u).hostname or "").lower()
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return bool(_INTERNAL_HOST.search(host)) or host == "localhost"


def analyze_js(sources):
    """sources: [(origin label, text)] -> {"files", "endpoints", "internal_urls", "secrets"}."""
    endpoints, internal, secrets = set(), set(), {}
    for origin, text in sources:
        for m in _ENDPOINT_RX.finditer(text):
            if len(endpoints) < 300:
                endpoints.add(m.group(1))
        for m in _URL_RX.finditer(text):
            if _is_internal_url(m.group(0)) and len(internal) < 100:
                internal.add(m.group(0).rstrip(".,;"))
        for name, rx in _SECRET_RX:
            for m in rx.finditer(text):
                value = m.group(m.lastindex) if name == "Secret générique" else m.group(0)
                if name == "Secret générique" and (_PLACEHOLDER.match(value) or len(set(value)) < 6):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                if value not in secrets:  # specific rules run first: a value is reported once
                    secrets[value] = {"type": name, "value": mask(value), "where": f"{origin}:{line}"}
    return {"files": [o for o, _ in sources], "endpoints": sorted(endpoints),
            "internal_urls": sorted(internal), "secrets": list(secrets.values())}


def same_site(url, page_url):
    a = (urllib.parse.urlsplit(url).hostname or "").lower()
    b = (urllib.parse.urlsplit(page_url).hostname or "").lower()
    if not a or not b:
        return False
    if a == b:
        return True
    try:
        ipaddress.ip_address(b)
        return False
    except ValueError:
        pass
    root = ".".join(b.split(".")[-2:])
    return a == root or a.endswith("." + root)


class ScriptCollector:
    """Keeps the bodies of the scripts the page loads (same site only), with no extra request."""

    def __init__(self, page):
        self.responses = []
        page.on("response", self._on_response)

    def _on_response(self, resp):
        try:
            if resp.request.resource_type == "script" and len(self.responses) < JS_MAX_FILES:
                self.responses.append(resp)
        except Exception:
            pass

    async def sources(self, page_url, page_html):
        out = []
        for resp in self.responses:
            if not same_site(resp.url, page_url):
                continue
            try:
                body = await resp.body()
            except Exception:
                continue
            out.append((resp.url, body[:JS_MAX_BYTES].decode("utf-8", "replace")))
        inline = "\n".join(_INLINE_RX.findall(page_html or ""))
        if inline.strip():
            out.append((f"{page_url} (inline)", inline))
        return out


# --- Subdomain takeover --------------------------------------------------------------------------
# (CNAME suffix, service, page fingerprint or None = dangling only when the CNAME target does not exist)

TAKEOVER = [
    (".s3.amazonaws.com", "AWS S3", r"NoSuchBucket|The specified bucket does not exist"),
    (".s3-website", "AWS S3 (site)", r"NoSuchBucket"),
    (".github.io", "GitHub Pages", r"There isn't a GitHub Pages site here"),
    (".herokuapp.com", "Heroku", r"no-such-app|No such app"),
    (".herokudns.com", "Heroku", r"no-such-app|No such app"),
    (".azurewebsites.net", "Azure App Service", None),
    (".cloudapp.net", "Azure Cloud Service", None),
    (".cloudapp.azure.com", "Azure VM", None),
    (".trafficmanager.net", "Azure Traffic Manager", None),
    (".blob.core.windows.net", "Azure Blob", r"The specified resource does not exist|BlobServiceProperties|InvalidQueryParameterValue"),
    (".azureedge.net", "Azure CDN", None),
    (".azure-api.net", "Azure API Management", None),
    (".azurefd.net", "Azure Front Door", None),
    (".elasticbeanstalk.com", "AWS Elastic Beanstalk", None),
    (".wordpress.com", "WordPress.com", r"Do you want to register"),
    (".ghost.io", "Ghost", r"The thing you were looking for is no longer here"),
    (".pantheonsite.io", "Pantheon", r"The gods are wise"),
    (".zendesk.com", "Zendesk", r"Help Center Closed"),
    (".myshopify.com", "Shopify", r"Sorry, this shop is currently unavailable"),
    (".fastly.net", "Fastly", r"Fastly error: unknown domain"),
    (".surge.sh", "Surge", r"project not found"),
    (".bitbucket.io", "Bitbucket", r"Repository not found"),
    (".readthedocs.io", "Read the Docs", r"unknown to Read the Docs"),
    (".netlify.app", "Netlify", r"Not Found - Request ID"),
    (".helpscoutdocs.com", "Help Scout", r"No settings were found for this company"),
    (".helpjuice.com", "Helpjuice", r"We could not find what you're looking for"),
    (".freshdesk.com", "Freshdesk", r"May be this is still fresh"),
    (".uservoice.com", "UserVoice", r"This UserVoice subdomain is currently available"),
    (".teamwork.com", "Teamwork", r"Oops - We didn't find your site"),
    (".tumblr.com", "Tumblr", r"Whatever you were looking for doesn't currently exist at this address"),
    (".webflow.io", "Webflow", r"The page you are looking for doesn't exist or has been moved"),
    (".agilecrm.com", "Agile CRM", r"Sorry, this page is no longer available"),
    (".ngrok.io", "ngrok", r"Tunnel .* not found"),
]


def _dns_servers():
    from .dns import _split_server, system_dns_servers
    servers = [_split_server(s) for s in system_dns_servers()]
    return servers or [("1.1.1.1", 53)]


def cname_chain(name, servers=None):
    """-> ([cname targets in order], final target exists?) using the DNS module."""
    from .dns import query
    servers = servers or _dns_servers()
    chain, cur = [], name
    for _ in range(8):
        recs = None
        for host, port in servers:
            try:
                recs, rcode = query(host, port, cur, 5, timeout=3.0)  # 5 = CNAME
                break
            except (OSError, ValueError):
                continue
        targets = [r["data"].rstrip(".") for r in recs or [] if r["type"] == "CNAME"]
        if not targets:
            break
        cur = targets[0].lower()
        chain.append(cur)
    if not chain:
        return [], True
    # Dangling only when a resolver positively answers NXDOMAIN; no answer at all proves nothing
    for host, port in servers:
        try:
            recs, rcode = query(host, port, chain[-1], 1, timeout=3.0)  # A
        except (OSError, ValueError):
            continue
        return chain, rcode != 3
    return chain, True


def check_takeover(hostnames, page_text_by_host, log=print):
    """-> [{"host", "cname", "service", "reason", "level"}] for the names that look takeable."""
    from concurrent.futures import ThreadPoolExecutor
    servers = _dns_servers()
    names = sorted({h.lower().rstrip(".") for h in hostnames})
    with ThreadPoolExecutor(max_workers=16) as pool:
        chains = list(pool.map(lambda n: cname_chain(n, servers), names))
    out = []
    for name, (chain, exists) in zip(names, chains):
        if not chain:
            continue
        service = ""
        fp = None
        for suffix, svc, rx in TAKEOVER:
            if any(suffix in c for c in chain):
                service, fp = svc, rx
                break
        page = page_text_by_host.get(name, "")
        if not exists:
            out.append({"host": name, "cname": " -> ".join(chain), "service": service or "inconnu",
                        "reason": "la cible du CNAME n'existe plus (NXDOMAIN)",
                        "level": "haute" if service else "moyenne"})
        elif fp and page and re.search(fp, page):
            out.append({"host": name, "cname": " -> ".join(chain), "service": service,
                        "reason": "la page du service indique une ressource inexistante", "level": "haute"})
    if out:
        log(f"[takeover] {len(out)} sous-domaine(s) à vérifier (CNAME orphelin)")
    return out


# --- Banners of non-web services ----------------------------------------------------------------

BANNER_RULES = [
    ("OpenSSH", ["openbsd:openssh"], r"SSH-[\d.]+-OpenSSH_([\w.]+)"),
    ("Dropbear SSH", ["dropbear_ssh_project:dropbear_ssh"], r"SSH-[\d.]+-dropbear_([\d.]+)"),
    ("SSH", [], r"^SSH-[\d.]+-(\S+)"),
    ("vsftpd", ["beasts:vsftpd"], r"vsFTPd ([\d.]+)"),
    ("ProFTPD", ["proftpd:proftpd"], r"ProFTPD ([\d.]+\w*)"),
    ("Pure-FTPd", [], r"Pure-FTPd"),
    ("FileZilla Server", ["filezilla-project:filezilla_server"], r"FileZilla Server(?: version)? ([\d.]+)"),
    ("Microsoft FTP", [], r"Microsoft FTP Service"),
    ("FTP", [], r"^220[ -]"),
    ("Postfix", ["postfix:postfix"], r"ESMTP Postfix"),
    ("Exim", ["exim:exim"], r"Exim ([\d.]+)"),
    ("Microsoft Exchange SMTP", [], r"Microsoft ESMTP MAIL Service"),
    ("Sendmail", ["sendmail:sendmail"], r"Sendmail ([\d.]+)"),
    ("Dovecot", ["dovecot:dovecot"], r"Dovecot"),
    ("POP3", [], r"^\+OK"),
    ("IMAP", [], r"^\* OK"),
    ("MariaDB", ["mariadb:mariadb"], r"([\d.]+)-MariaDB"),
    ("MySQL", ["oracle:mysql"], r"^.{4}\x0a(\d+\.\d+\.\d+)"),
    ("Redis", ["redis:redis"], r"redis_version:([\d.]+)"),
    ("Redis", ["redis:redis"], r"^-NOAUTH"),
    ("Telnet", [], r"^\xff[\xfb-\xfe]"),
    ("VNC", [], r"^RFB (\d{3}\.\d{3})"),
    ("RDP", [], r"^\x03\x00"),
]
_BANNER_RX = [(n, c, re.compile(rx, re.S)) for n, c, rx in BANNER_RULES]
_RDP_PROBE = bytes.fromhex("030000130ee000000000000100080003000000")


async def open_tcp(host, port, timeout, proxy=None):
    """TCP connection, direct or through a SOCKS5 proxy."""
    if not proxy or proxy.get("scheme") != "socks5":
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    reader, writer = await asyncio.wait_for(asyncio.open_connection(proxy["host"], proxy["port"]), timeout)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    await asyncio.wait_for(reader.readexactly(2), timeout)
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        addr = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
    except ValueError:
        name = host.encode("idna")
        addr = b"\x03" + bytes([len(name)]) + name
    writer.write(b"\x05\x01\x00" + addr + struct.pack(">H", port))
    await writer.drain()
    head = await asyncio.wait_for(reader.readexactly(4), timeout)
    if head[1] != 0:
        writer.close()
        raise OSError("socks: connection refused")
    n = {1: 4, 4: 16}.get(head[3])
    if n is None:
        n = (await reader.readexactly(1))[0]  # domain name: length byte first
    await reader.readexactly(n + 2)  # bound address + port
    return reader, writer


async def grab_banner(host, port, timeout=3.0, proxy=None):
    """First bytes a service sends (or answers to a harmless probe). -> text ('' if nothing)."""
    async def talk(probe):
        reader, writer = await open_tcp(host, port, timeout, proxy)
        try:
            if probe:
                writer.write(probe)
                await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout)
            return data
        finally:
            writer.close()

    try:
        if port == 3389:
            return (await talk(_RDP_PROBE)).decode("latin-1")
        try:
            data = await talk(None)  # most services speak first (SSH, FTP, SMTP, POP, IMAP, MySQL, VNC)
        except asyncio.TimeoutError:
            data = b""
        if not data:  # silent service: one harmless probe (Redis answers INFO, others an error line)
            data = await talk(b"INFO server\r\n" if port == 6379 else b"\r\n")
        return data.decode("latin-1")
    except Exception:
        return ""


def parse_banner(text):
    """-> (service name, version, cpes) from a banner, or ("", "", [])."""
    for name, cpes, rx in _BANNER_RX:
        m = rx.search(text)
        if m:
            return name, (m.group(1) if m.groups() else ""), cpes
    return "", "", []


def banner_display(text):
    printable = "".join(c if 32 <= ord(c) < 127 else " " for c in text)
    return re.sub(r"\s+", " ", printable).strip()[:160]


# --- HTML for report.html -------------------------------------------------------------------------

RECON_CSS = """
.sev-critique{background:#b00;color:#fff}.sev-haute{background:#c60;color:#fff}
.sev-moyenne{background:#da3;color:#000}.sev-info{background:#999;color:#fff}
.sev{border-radius:3px;padding:1px 6px;font-size:12px}
code.bn{font-size:12px;background:#eee;padding:1px 4px}
"""


def _sev(s):
    return f'<span class="sev sev-{s}">{html.escape(s)}</span>'


def _link(u):
    return f'<a href="{html.escape(u)}">{html.escape(u)}</a>'


def files_section(results):
    rows = []
    seen = set()
    for r in results:
        for f in r.get("files_found") or []:
            if f["url"] in seen:
                continue
            seen.add(f["url"])
            rows.append((SEVERITY[f["severity"]], f"<tr><td>{_sev(f['severity'])}</td><td>{_link(f['url'])}</td>"
                         f"<td>{f['size']} o</td></tr>"))
    if not rows:
        return ""
    rows.sort(key=lambda x: x[0])
    return (f"<details open><summary><b>Fichiers sensibles exposés</b> - {len(rows)}</summary><table>"
            f"<tr><th>Gravité</th><th>URL</th><th>Taille lue</th></tr>{''.join(r for _, r in rows)}</table></details>")


def js_section(results):
    rows = []
    seen = set()
    for r in results:
        js = r.get("js") or {}
        if not (js.get("secrets") or js.get("endpoints") or js.get("internal_urls")):
            continue
        base = urllib.parse.urlsplit(r.get("final_url") or r["url"])
        key = (base.scheme, base.netloc)
        if key in seen:
            continue
        seen.add(key)
        sec = "<br>".join(f"<b>{html.escape(s['type'])}</b> <code>{html.escape(s['value'])}</code> "
                          f"<i>{html.escape(s['where'])}</i>" for s in js.get("secrets") or [])
        eps = js.get("endpoints") or []
        ep = ", ".join(f"<code>{html.escape(e)}</code>" for e in eps[:40]) + (f" +{len(eps) - 40}" if len(eps) > 40 else "")
        internal = "<br>".join(html.escape(u) for u in (js.get("internal_urls") or [])[:20])
        rows.append(f"<tr><td>{_link(r['url'])}<br><i>{len(js.get('files') or [])} script(s)</i></td>"
                    f"<td>{sec}</td><td>{internal}</td><td>{ep}</td></tr>")
    if not rows:
        return ""
    n_sec = sum(len((r.get("js") or {}).get("secrets") or []) for r in results)
    return (f"<details open><summary><b>JavaScript</b> - {len(rows)} service(s), {n_sec} secret(s) possible(s) "
            f"(valeurs masquées)</summary><table><tr><th>Service</th><th>Secrets possibles</th>"
            f"<th>URL internes</th><th>Chemins d'API</th></tr>{''.join(rows)}</table></details>")


def wellknown_section(results):
    rows = []
    seen = set()
    for r in results:
        w = r.get("well_known") or {}
        if not w:
            continue
        base = urllib.parse.urlsplit(r.get("url"))
        key = (base.scheme, base.netloc)
        if key in seen:
            continue
        seen.add(key)
        root = f"{base.scheme}://{base.netloc}"
        robots = "<br>".join(_link(root + p if p.startswith("/") else p) for p in (w.get("robots") or [])[:40])
        if len(w.get("robots") or []) > 40:
            robots += f"<br>+{len(w['robots']) - 40}"
        sm = ""
        if w.get("sitemap_urls"):
            sm = f"{w['sitemap_urls']} URL<br>" + "<br>".join(_link(u) for u in w.get("sitemap_sample")[:8])
        sec = ""
        if w.get("security"):
            s = w["security"]
            sec = "<br>".join(f"{k} : {html.escape(', '.join(v))}" for k, v in s.items() if k != "url")
        rows.append(f"<tr><td>{_link(root + '/')}</td><td>{robots}</td><td>{sm}</td><td>{sec}</td></tr>")
    if not rows:
        return ""
    return (f"<details><summary><b>robots.txt, sitemap, security.txt</b> - {len(rows)} service(s)</summary>"
            f"<table><tr><th>Service</th><th>Chemins de robots.txt</th><th>Sitemap</th><th>security.txt</th></tr>"
            f"{''.join(rows)}</table></details>")


def takeover_section(takeovers):
    if not takeovers:
        return ""
    rows = "".join(f"<tr><td>{_sev(t['level'])}</td><td>{html.escape(t['host'])}</td><td>{html.escape(t['cname'])}</td>"
                   f"<td>{html.escape(t['service'])}</td><td>{html.escape(t['reason'])}</td></tr>" for t in takeovers)
    return (f"<details open><summary><b>Prise de contrôle de sous-domaine possible</b> - {len(takeovers)}</summary>"
            f"<table><tr><th>Gravité</th><th>Nom</th><th>Chaîne CNAME</th><th>Service</th><th>Raison</th></tr>"
            f"{rows}</table></details>")


def banners_section(results):
    rows = [f"<tr><td>{html.escape(r['host'])}:{r['port']}</td><td>{html.escape(r.get('service') or '?')}</td>"
            f"<td>{html.escape(r.get('service_version') or '')}</td><td><code class=\"bn\">{html.escape(r.get('banner') or '')}</code></td>"
            f"<td>{html.escape(DEFAULT_CREDS.get(r.get('service') or '', ''))}</td></tr>"
            for r in results if r.get("banner") or r.get("service")]
    if not rows:
        return ""
    return (f"<details open><summary><b>Services non web</b> - {len(rows)}</summary><table><tr><th>Service</th>"
            f"<th>Produit</th><th>Version</th><th>Bannière</th><th>Identifiants par défaut connus</th></tr>"
            f"{''.join(rows)}</table></details>")
