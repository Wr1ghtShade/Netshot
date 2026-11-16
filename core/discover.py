"""
core/discover.py - wider discovery around the scanned organisation and "Top risques" summary.
Same behaviour as discover.go and risks.go (netshot-go):

- certificate pivot: names of the certificates served on 443 by the targets (SAN); those of the
  organisation's domains are added to the scan. The organisation names (O=) of these certificates
  are searched in crt.sh: the domains certified under the same name are added too.
- IP blocks registered to the organisation (RDAP of the public IPs found): listed, never added.
- UDP (--udp, active): DNS (open resolver), NTP, SNMP (v3 discovery, no community tried), IKE,
  OpenVPN, SSDP on each target IP.
- IPv4 / IPv6 parity: the scanned ports of the dual-stack names on both families; a port open in
  IPv6 only is a forgotten firewall rule.
- Code leaks (key "github"): GitHub code search of the organisation's domains (repository, file and
  link only; the files are not downloaded).
- "Top risques": the findings of every check, ranked, at the top of the report.
"""

import csv
import html
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from .sources import get_json, is_internal_ip, registrable_domain

SEVERITY_RANK = {"critique": 0, "haute": 1, "moyenne": 2, "info": 3}
CERT_ORG_SKIP = ["cloudflare", "amazon", "google", "microsoft", "akamai", "fastly", "automattic", "github",
                 "heroku", "salesforce", "ovh", "wix", "squarespace", "shopify", "incapsula", "imperva", "sucuri",
                 "zscaler", "let's encrypt", "digicert", "sectigo", "globalsign", "atlassian", "okta", "zendesk"]
GITHUB_API = "https://api.github.com"


def new_extra():
    return {"cert_orgs": [], "cert_names": [], "org_domains": [], "netblocks": [], "udp": [], "udp_note": "",
            "ipv6_parity": [], "ipv6_note": "", "github": [], "github_note": ""}


def _is_ip(text):
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        return False


def _resolves(name):
    try:
        return bool(socket.getaddrinfo(name, None))
    except (socket.gaierror, UnicodeError, OSError):
        return False


# --- Certificate pivot --------------------------------------------------------------------------

def skip_org(o):
    lo = o.lower()
    return len(lo.strip()) < 4 or any(s in lo for s in CERT_ORG_SKIP)


def peek_cert(host):
    """(SAN names, organisations) of the certificate served on host:443."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host.strip("[]"), 443), timeout=4) as raw:
            with ctx.wrap_socket(raw, server_hostname=None if _is_ip(host) else host) as s:
                s.settimeout(5)
                der = s.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError):
        return [], []
    if not der:
        return [], []
    from .tls import parse_cert
    try:
        info = parse_cert(der)
    except (ValueError, IndexError, KeyError, UnicodeDecodeError):
        return [], []
    names = [n for n in info["sans"] if not _is_ip(n)]
    orgs = re.findall(r"(?:^|,)O=([^,]+)", info["subject"])
    return names, orgs


def cert_pivot(hosts, own, ext, log=print, stop=None):
    """Reads the certificates of the targets; returns the names of the organisation's domains to add."""
    targets = hosts[:300]
    with ThreadPoolExecutor(32) as pool:
        peeks = list(pool.map(lambda h: ([], []) if stop and stop.is_set() else peek_cert(h), targets))
    known = {h.lower() for h in hosts}
    add, seen = [], set()
    for host, (names, orgs) in zip(targets, peeks):
        for o in orgs:
            if not skip_org(o) and o not in ext["cert_orgs"]:
                ext["cert_orgs"].append(o)
        for n in names:
            n = n.lower().removeprefix("*.")
            if not n or n in seen or n in known or "." not in n:
                continue
            seen.add(n)
            p = {"name": n, "via": f"certificat de {host}:443", "added": False}
            if registrable_domain(n) in own and _resolves(n):
                p["added"] = True
                add.append(n)
                known.add(n)
            ext["cert_names"].append(p)
    if ext["cert_names"]:
        log(f"[pivot] {len(ext['cert_names'])} nom(s) lus dans les certificats, {len(add)} ajouté(s) au scan")
    return add


def crtsh_org(org):
    """Registrable domains certified under the organisation name org (crt.sh O=), most frequent first."""
    url = "https://crt.sh/?O=" + urllib.parse.quote(org) + "&output=json&exclude=expired"
    count = Counter()
    for row in get_json("crt.sh", url, timeout=45) or []:
        for n in (row.get("name_value") or "").split("\n") + [row.get("common_name") or ""]:
            n = n.strip().removeprefix("*.").strip().lower()
            if not n or "." not in n or _is_ip(n) or " " in n or "@" in n:
                continue
            count[registrable_domain(n)] += 1
    return sorted(count, key=lambda d: (-count[d], d))


def org_pivot(own, known, ext, log=print, stop=None):
    """crt.sh by organisation name (3 names at most); new domains to add (25 at most, those that
    resolve). A large organisation can have thousands of certified domains: 100 are examined at
    most, resolved in parallel, and the report lists those 100 only."""
    add = []
    for o in ext["cert_orgs"][:3]:
        if stop and stop.is_set():
            break
        try:
            domains = crtsh_org(o)
        except (RuntimeError, OSError, ValueError) as exc:
            log(f"[pivot] crt.sh O={o} : {exc}")
            continue
        fresh = [d for d in domains if d not in own and d not in known][:100]
        with ThreadPoolExecutor(16) as pool:
            alive = list(pool.map(lambda x: False if stop and stop.is_set() else _resolves(x), fresh))
        n = 0
        for d, ok in zip(fresh, alive):
            p = {"name": d, "via": f"crt.sh O={o}", "added": False}
            if ok and n < 25:
                p["added"] = True
                add.append(d)
                known.add(d)
                own.add(d)
                n += 1
            ext["org_domains"].append(p)
        more = f" ({len(domains) - len(fresh)} déjà connus ou au-delà des 100 examinés)" if len(domains) > len(fresh) else ""
        log(f"[pivot] crt.sh O={o} : {len(domains)} domaine(s){more}, {n} ajouté(s) au scan")
    return add


# --- RDAP netblocks -----------------------------------------------------------------------------

def norm_term(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def org_terms(ext, cloud, own):
    out = []

    def add(s):
        t = norm_term(s)
        if len(t) >= 4 and t not in out:
            out.append(t)
    for o in ext["cert_orgs"]:
        add((o.split() or [""])[0])
        add(o)
    for t in (cloud or {}).get("tenants", []):
        add(t.get("brand", ""))
    for d in sorted(own):
        add(d.split(".")[0])
    return out


def find_netblocks(ips, cloud_ips, terms, ext, log=print, stop=None):
    """RDAP record of the public IPs (40 at most): blocks whose name or holder matches the organisation."""
    from .whois import _vcard, _walk_entities, rdap_lookup
    if not terms:
        return
    seen, n = set(), 0
    for ip in ips:
        if n >= 40 or (stop and stop.is_set()):
            break
        if ip in cloud_ips:
            continue
        addr = ipaddress.ip_address(ip)
        if any("/" in b["cidr"] and addr in ipaddress.ip_network(b["cidr"], strict=False) for b in ext["netblocks"]):
            continue
        n += 1
        try:
            data = rdap_lookup("ip", ip)[3]
        except (LookupError, OSError, ValueError, urllib.error.URLError):
            continue
        name, handle = data.get("name", ""), data.get("handle", "")
        roles = _walk_entities(data.get("entities"), {})
        holder = ""
        for role in ("registrant", "administrative"):
            if roles.get(role):
                v = _vcard(roles[role][0])
                holder = f"{v.get('org', '')} {v.get('fn', '')}".strip()
                break
        hay = norm_term(f"{name} {holder} {json.dumps(data.get('remarks', ''))}")
        match = next((t for t in terms if t in hay), "")
        if not match:
            continue
        cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c['length']}" for c in data.get("cidr0_cidrs", [])
                 if (c.get("v4prefix") or c.get("v6prefix")) and "length" in c]
        if not cidrs and data.get("startAddress"):
            cidrs = [f"{data['startAddress']} - {data.get('endAddress', '')}"]
        for c in cidrs:
            if c in seen:
                continue
            seen.add(c)
            size = 0
            if "/" in c:
                net = ipaddress.ip_network(c, strict=False)
                if net.version == 4:
                    if net.prefixlen < 16:
                        continue  # too wide to be the organisation's own block (a provider's)
                    size = net.num_addresses
            ext["netblocks"].append({"cidr": c, "name": name, "org": holder, "handle": handle, "match": match,
                                     "from_ip": ip, "size": size, "scanned": 0})
    for b in ext["netblocks"]:
        if "/" in b["cidr"]:
            net = ipaddress.ip_network(b["cidr"], strict=False)
            b["scanned"] = sum(1 for ip in ips if ipaddress.ip_address(ip) in net)
    if ext["netblocks"]:
        log(f"[pivot] {len(ext['netblocks'])} bloc(s) d'IP au nom de l'organisation (à ajouter au périmètre si "
            f"le client confirme)")


# --- UDP ----------------------------------------------------------------------------------------

def dns_probe_packet():
    """Recursive query for example.com A: an answer with RA and records = open resolver."""
    q = bytes([0x13, 0x37, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
    for label in ("example", "com"):
        q += bytes([len(label)]) + label.encode()
    return q + bytes([0, 0, 1, 0, 1])


def _tlv(tag, *content):
    body = b"".join(content)
    n = len(body)
    return bytes([tag, n]) + body if n < 128 else bytes([tag, 0x82, n >> 8, n & 0xff]) + body


def _ber_int(v):
    b = v.to_bytes(4, "big")
    while len(b) > 1 and b[0] == 0 and b[1] < 0x80:
        b = b[1:]
    return _tlv(0x02, b)


def snmp_discovery():
    """SNMPv3 engine discovery (RFC 3414 §4), no community and no user."""
    usm = _tlv(0x30, _tlv(0x04), _ber_int(0), _ber_int(0), _tlv(0x04), _tlv(0x04), _tlv(0x04))
    header = _tlv(0x30, _ber_int(0x1337), _ber_int(65507), _tlv(0x04, b"\x04"), _ber_int(3))
    pdu = _tlv(0xa0, _ber_int(0x2a), _ber_int(0), _ber_int(0), _tlv(0x30))
    return _tlv(0x30, _ber_int(3), header, _tlv(0x04, usm), _tlv(0x30, _tlv(0x04), _tlv(0x04), pdu))


def ike_packet():
    """IKEv1 Main Mode, one proposal (AES-128, SHA1, group 2, PSK) as ike-scan sends."""
    attrs = bytes([0x80, 0x01, 0x00, 0x07, 0x80, 0x0e, 0x00, 0x80, 0x80, 0x02, 0x00, 0x02, 0x80, 0x04, 0x00, 0x02,
                   0x80, 0x03, 0x00, 0x01, 0x80, 0x0b, 0x00, 0x01, 0x80, 0x0c, 0x70, 0x80])
    transform = struct.pack(">BBHBBH", 0, 0, 8 + len(attrs), 1, 1, 0) + attrs
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
    sa = struct.pack(">BBHII", 0, 0, 12 + len(proposal), 1, 1) + proposal
    hdr = os.urandom(8) + bytes(8) + bytes([1, 0x10, 2, 0]) + struct.pack(">II", 0, 28 + len(sa))
    return hdr + sa


def _dns_read(r):
    if len(r) < 12:
        return "répond", "info"
    ra, rcode, answers = r[3] & 0x80, r[3] & 0x0f, struct.unpack(">H", r[6:8])[0]
    if ra and answers and rcode == 0:
        return "résolveur ouvert : résout pour n'importe qui (amplification DDoS, empoisonnement)", "haute"
    return "serveur DNS (récursion refusée)", "info"


def _ssdp_read(r):
    d = "UPnP exposé sur Internet (amplification DDoS, équipement grand public)"
    for line in r.decode("latin-1").split("\r\n"):
        if line.upper().startswith("SERVER:"):
            d += " - " + line[7:].strip()
    return d, "moyenne"


UDP_PROBES = [
    (53, "DNS", dns_probe_packet, _dns_read),
    (123, "NTP", lambda: b"\x23" + bytes(47),
     lambda r: (f"serveur NTP (strate {r[1]})" if len(r) >= 2 else "répond", "info")),
    (161, "SNMP", snmp_discovery, lambda r: ("SNMP exposé sur Internet (identifiant moteur SNMPv3 obtenu)", "moyenne")),
    (500, "IKE (VPN IPsec)", ike_packet, lambda r: ("passerelle VPN IPsec (IKE répond)", "info")),
    (1194, "OpenVPN", lambda: b"\x38" + os.urandom(8) + bytes(5),
     lambda r: ("serveur OpenVPN (sans tls-auth : répond à un inconnu)", "info")),
    (1900, "SSDP (UPnP)", lambda: (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
                                   b"MX: 1\r\nST: ssdp:all\r\n\r\n"), _ssdp_read),
]


def _udp_ask(ip, port, payload):
    for _ in range(2):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.connect((ip, port))
                s.send(payload())
                data = s.recv(4096)
                if data:
                    return data
        except OSError:
            continue
    return None


def probe_udp(ip_hosts, ext, log=print, stop=None):
    ips = sorted(ip_hosts)
    if len(ips) > 256:
        ext["udp_note"] = f"{len(ips)} IP, seules les 256 premières sondées"
        ips = ips[:256]
    log(f"[udp] {len(ips)} IP x {len(UDP_PROBES)} sondes (DNS, NTP, SNMP, IKE, OpenVPN, SSDP)")
    lock = threading.Lock()

    def one(job):
        ip, (port, service, payload, read) = job
        if stop and stop.is_set():
            return
        r = _udp_ask(ip, port, payload)
        if r:
            detail, sev = read(r)
            with lock:
                ext["udp"].append({"ip": ip, "host": ", ".join(ip_hosts.get(ip) or []), "port": port,
                                   "service": service, "detail": detail, "severity": sev})
    with ThreadPoolExecutor(32) as pool:
        list(pool.map(one, [(ip, p) for ip in ips for p in UDP_PROBES]))
    ext["udp"].sort(key=lambda u: (SEVERITY_RANK.get(u["severity"], 9), u["ip"], u["port"]))
    log(f"[udp] {len(ext['udp'])} service(s) UDP répondent")


# --- IPv4 / IPv6 parity -------------------------------------------------------------------------

def has_ipv6():
    """Can this machine reach the IPv6 Internet? (a UDP "connection" sends nothing)"""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(("2001:4860:4860::8888", 53))
        return True
    except OSError:
        return False


def _open(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_parity(names, ports, timeout, ext, log=print, stop=None):
    pairs = []
    for n in names:
        if len(pairs) >= 50:
            break
        try:
            infos = socket.getaddrinfo(n, None, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, UnicodeError, OSError):
            continue
        v4 = next((i[4][0] for i in infos if i[0] == socket.AF_INET), "")
        v6 = next((i[4][0] for i in infos if i[0] == socket.AF_INET6
                   and ipaddress.ip_address(i[4][0]).is_global), "")
        if v4 and v6 and not is_internal_ip(v4):
            pairs.append((n, v4, v6))
    if not pairs:
        return
    if not has_ipv6():
        ext["ipv6_note"] = f"{len(pairs)} nom(s) double pile, mais pas d'accès IPv6 depuis ce poste : parité non vérifiée"
        log(f"[ipv6] {ext['ipv6_note']}")
        return
    log(f"[ipv6] parité IPv4 / IPv6 de {len(pairs)} nom(s) double pile sur {len(ports)} port(s)")
    jobs = [(ip, p) for _, v4, v6 in pairs for p in ports for ip in (v4, v6)]
    with ThreadPoolExecutor(64) as pool:
        opened = {job for job, ok in zip(jobs, pool.map(
            lambda j: False if stop and stop.is_set() else _open(j[0], j[1], timeout), jobs)) if ok}
    if stop and stop.is_set():
        return
    for host, v4, v6 in pairs:
        v6_only = [p for p in ports if (v6, p) in opened and (v4, p) not in opened]
        v4_only = [p for p in ports if (v4, p) in opened and (v6, p) not in opened]
        if v6_only or v4_only:
            ext["ipv6_parity"].append({"host": host, "ipv4": v4, "ipv6": v6, "v6_only": v6_only, "v4_only": v4_only})
    log(f"[ipv6] {len(ext['ipv6_parity'])} nom(s) avec des ports différents entre IPv4 et IPv6")


# --- GitHub -------------------------------------------------------------------------------------

def search_github(domains, token, ext, log=print, stop=None):
    """Organisation's domains in public code (3 domains, 2 queries each, 7 s apart: 10 requests / minute)."""
    seen, first = set(), True
    for d in domains[:3]:
        for q in (f'"{d}"', f'"{d}" password OR secret OR token OR apikey'):
            if stop and stop.is_set():
                return
            if not first:
                if stop and stop.wait(7):
                    return
                if not stop:
                    time.sleep(7)
            first = False
            req = urllib.request.Request(f"{GITHUB_API}/search/code?per_page=30&q={urllib.parse.quote(q)}", headers={
                "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "Netshot"})
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:
                    res = json.loads(resp.read(8 << 20))
            except urllib.error.HTTPError as exc:
                if exc.code == 401:
                    ext["github_note"] = "jeton GitHub refusé (HTTP 401)"
                elif exc.code in (403, 429):
                    ext["github_note"] = f"limite de recherche GitHub atteinte (HTTP {exc.code}) : résultats partiels"
                else:
                    continue
                log(f"[github] {ext['github_note']}")
                return
            except (urllib.error.URLError, OSError, ValueError) as exc:
                ext["github_note"] = str(exc)
                return
            for it in res.get("items", []):
                url = it.get("html_url", "")
                if url and url not in seen:
                    seen.add(url)
                    ext["github"].append({"repo": (it.get("repository") or {}).get("full_name", ""),
                                          "path": it.get("path", ""), "url": url, "query": q})
            log(f"[github] {q} : {res.get('total_count', 0)} fichier(s)")


# --- Run ----------------------------------------------------------------------------------------

def resolve_targets(hosts):
    """{IPv4 of every target: [names]} (256 names resolved at most)."""
    out, n = {}, 0
    for h in hosts:
        h = h.strip("[]")
        if _is_ip(h):
            if ipaddress.ip_address(h).version == 4:
                out.setdefault(h, [])
            continue
        if n >= 256:
            continue
        n += 1
        try:
            for info in socket.getaddrinfo(h, None, socket.AF_INET, proto=socket.IPPROTO_TCP):
                lst = out.setdefault(info[4][0], [])
                if h not in lst:
                    lst.append(h)
        except (socket.gaierror, UnicodeError, OSError):
            continue
    return out


def run_extra_checks(args, hosts, ports, own_domains, cloud, ext, outdir, log=print, stop=None):
    """Post-scan checks: netblocks, UDP, IPv6 parity, GitHub; writes discovery.csv."""
    pivot, udp = getattr(args, "pivot", True), getattr(args, "udp", False)
    proxy = getattr(args, "proxy", None)
    ip_hosts = resolve_targets(hosts) if (pivot or udp) else {}
    if pivot and ip_hosts and not (stop and stop.is_set()):
        cloud_ips = {x["ip"] for x in (cloud or {}).get("ips", [])}
        public = sorted(ip for ip in ip_hosts if not is_internal_ip(ip))
        find_netblocks(public, cloud_ips, org_terms(ext, cloud, set(own_domains)), ext, log, stop)
    if udp and not (stop and stop.is_set()):
        if proxy:
            ext["udp_note"] = "sondes UDP impossibles à travers le proxy : non lancées"
            log(f"[udp] {ext['udp_note']}")
        elif ip_hosts:
            probe_udp(ip_hosts, ext, log, stop)
    if getattr(args, "ipv6_parity", True) and not proxy and not (stop and stop.is_set()):
        names = [h for h in hosts if not _is_ip(h)]
        if names:
            check_parity(names, list(ports), getattr(args, "connect_timeout", 3), ext, log, stop)
    token = (getattr(args, "keys", None) or {}).get("github", "")
    if token and own_domains and not (stop and stop.is_set()):
        search_github(sorted(own_domains), token, ext, log, stop)
    if not extra_empty(ext) and outdir.exists():
        with open(outdir / "discovery.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(EXTRA_HEADER)
            w.writerows(extra_rows(ext))


# --- Report -------------------------------------------------------------------------------------

def extra_empty(e):
    return not e or not (e["cert_names"] or e["org_domains"] or e["netblocks"] or e["udp"] or e["ipv6_parity"]
                         or e["github"] or e["ipv6_note"] or e["github_note"] or e["udp_note"])


def _added(b):
    return "ajouté au scan" if b else "hors organisation ou ne résout pas"


def _ints(lst):
    return ", ".join(map(str, lst))


def extra_sections(e):
    from .recon import _sev
    if extra_empty(e):
        return ""
    esc = html.escape
    out = []
    names = e["cert_names"] + e["org_domains"]
    if names or e["netblocks"]:
        out.append(f"<details><summary><b>Découverte élargie</b> - {len(names)} nom(s) ou domaine(s) trouvé(s), "
                   f"{sum(p['added'] for p in names)} ajouté(s) au scan, {len(e['netblocks'])} bloc(s) d'IP au nom "
                   f"de l'organisation</summary>")
        if e["cert_orgs"]:
            out.append(f"<p>Organisation(s) des certificats : {esc(', '.join(e['cert_orgs']))}</p>")
        if names:
            out.append("<table><tr><th>Nom</th><th>Trouvé par</th><th>Suite</th></tr>")
            out += [f"<tr><td>{esc(p['name'])}</td><td>{esc(p['via'])}</td><td>{_added(p['added'])}</td></tr>"
                    for p in names]
            out.append("</table>")
        if e["netblocks"]:
            out.append("<p>Blocs d'IP enregistrés au nom de l'organisation (RDAP) : <b>non scannés</b>, à ajouter au "
                       "périmètre si le client confirme qu'ils sont à lui.</p><table><tr><th>Bloc</th><th>Nom</th>"
                       "<th>Titulaire</th><th>Indice</th><th>Vu depuis</th><th>IP scannées</th></tr>")
            out += [f"<tr><td>{esc(b['cidr'])}</td><td>{esc(b['name'])}</td><td>{esc(b['org'])}</td>"
                    f"<td>{esc(b['match'])}</td><td>{esc(b['from_ip'])}</td><td>{b['scanned']} / {b['size']}</td></tr>"
                    for b in e["netblocks"]]
            out.append(f"</table><p>Cibles à copier : <code>{esc(' '.join(b['cidr'] for b in e['netblocks']))}</code></p>")
        out.append("</details>")
    if e["udp"] or e["udp_note"]:
        out.append(f"<details><summary><b>Services UDP</b> - {len(e['udp'])} réponse(s)</summary>")
        if e["udp_note"]:
            out.append(f"<p>{esc(e['udp_note'])}</p>")
        if e["udp"]:
            out.append("<table><tr><th>Gravité</th><th>IP</th><th>Noms</th><th>Port</th><th>Service</th><th>Constat</th></tr>")
            out += [f"<tr><td>{_sev(u['severity'])}</td><td>{esc(u['ip'])}</td><td>{esc(u['host'])}</td>"
                    f"<td>{u['port']}/udp</td><td>{esc(u['service'])}</td><td>{esc(u['detail'])}</td></tr>"
                    for u in e["udp"]]
            out.append("</table>")
        out.append("</details>")
    if e["ipv6_parity"] or e["ipv6_note"]:
        out.append(f"<details><summary><b>Parité IPv4 / IPv6</b> - {len(e['ipv6_parity'])} nom(s) avec des écarts</summary>")
        if e["ipv6_note"]:
            out.append(f"<p>{esc(e['ipv6_note'])}</p>")
        if e["ipv6_parity"]:
            out.append("<table><tr><th>Nom</th><th>IPv4</th><th>IPv6</th><th>Ouverts en IPv6 seulement</th>"
                       "<th>Ouverts en IPv4 seulement</th></tr>")
            for d in e["ipv6_parity"]:
                v6 = (_sev("haute") + " " + _ints(d["v6_only"])) if d["v6_only"] else ""
                out.append(f"<tr><td>{esc(d['host'])}</td><td>{esc(d['ipv4'])}</td><td>{esc(d['ipv6'])}</td>"
                           f"<td>{v6}</td><td>{_ints(d['v4_only'])}</td></tr>")
            out.append("</table>")
        out.append("</details>")
    if e["github"] or e["github_note"]:
        out.append(f"<details><summary><b>Code public (GitHub)</b> - {len(e['github'])} fichier(s) citant les domaines</summary>")
        if e["github_note"]:
            out.append(f"<p>{esc(e['github_note'])}</p>")
        if e["github"]:
            out.append("<p>Fichiers non téléchargés : à relire pour y chercher des identifiants, des clés ou des URL "
                       "internes.</p><table><tr><th>Dépôt</th><th>Fichier</th><th>Recherche</th></tr>")
            out += [f'<tr><td>{esc(h["repo"])}</td><td><a href="{esc(h["url"])}" target="_blank" rel="noopener">'
                    f'{esc(h["path"])}</a></td><td>{esc(h["query"])}</td></tr>' for h in e["github"]]
            out.append("</table>")
        out.append("</details>")
    return "".join(out)


EXTRA_HEADER = ["type", "item", "detail", "finding", "extra"]


def extra_rows(e):
    if not e:
        return []
    rows = [["nom", p["name"], p["via"], _added(p["added"]), ""] for p in e["cert_names"] + e["org_domains"]]
    rows += [["bloc IP", b["cidr"], f"{b['name']} / {b['org']}", f"indice {b['match']}, vu depuis {b['from_ip']}",
              f"{b['scanned']} / {b['size']} IP scannées"] for b in e["netblocks"]]
    rows += [["udp", u["ip"], f"{u['port']}/udp {u['service']}", u["detail"], u["severity"]] for u in e["udp"]]
    rows += [["ipv6", d["host"], f"{d['ipv4']} / {d['ipv6']}", "IPv6 seulement : " + _ints(d["v6_only"]),
              "IPv4 seulement : " + _ints(d["v4_only"])] for d in e["ipv6_parity"]]
    rows += [["github", h["repo"], h["path"], h["url"], h["query"]] for h in e["github"]]
    return rows


# --- Top risques --------------------------------------------------------------------------------

TAG_RISK = {"debug": ("haute", "Page de débogage exposée"),
            "admin": ("moyenne", "Interface d'administration exposée"),
            "index-of": ("moyenne", "Liste de fichiers ouverte (index of)")}


def collect_risks(results, exposures, tls_results, takeovers, reputation, cloud, ext):
    """Findings of every check, most severe first: {severity, title, asset, section}."""
    from .reputation import summary as rep_summary
    out = []

    def add(sev, title, asset, section):
        out.append({"severity": sev, "title": title, "asset": asset, "section": section})
    for x in exposures or []:
        hosts = x["ip"] + (f" ({', '.join(x['hosts'])})" if x.get("hosts") else "")
        for v in x.get("vulns") or []:
            if v.get("kev"):
                add("critique", f"Vulnérabilité exploitée activement (CISA KEV) : {v['cve']}", hosts, "Exposition des IP")
            elif (v.get("epss") or 0) >= 0.5:
                add("haute", f"Vulnérabilité à forte probabilité d'exploitation (EPSS {v['epss'] * 100:.0f} %) : "
                             f"{v['cve']}", hosts, "Exposition des IP")
        for leak in x.get("leaks") or []:
            add("haute", f"Fuite de données signalée par LeakIX : {leak}", hosts, "Exposition des IP")
    seen_tag = set()
    for r in results:
        svc = f"{r['host']}:{r['port']}"
        for f in r.get("files_found") or []:
            if f["severity"] in ("critique", "haute"):
                add(f["severity"], f"Fichier sensible exposé : /{f['path']}", f["url"], "Fichiers sensibles")
        for s in (r.get("js") or {}).get("secrets") or []:
            add("haute", f"Secret dans le JavaScript : {s['type']}", s["where"], "Analyse des pages")
        for t in r.get("tags") or []:
            if t in TAG_RISK and (svc, t) not in seen_tag:
                seen_tag.add((svc, t))
                add(TAG_RISK[t][0], TAG_RISK[t][1], r.get("final_url") or r.get("url", ""), "Pages sensibles")
    for t in tls_results or []:
        if t.get("grade") == "F":
            add("haute", "Configuration TLS dangereuse (note F)", t["target"], "TLS")
        elif t.get("grade") == "T":
            add("moyenne", "Certificat non reconnu (note T)", t["target"], "TLS")
    for t in takeovers or []:
        add("haute", f"Prise de contrôle de sous-domaine possible ({t['service']})", f"{t['host']} -> {t['cname']}",
            "Prise de contrôle de sous-domaine")
    for r in reputation or []:
        if r["level"] in ("critique", "haute"):
            add(r["level"], "Réputation : " + rep_summary(r), r["host"], "Réputation")
    if ext:
        for u in ext["udp"]:
            if u["severity"] != "info":
                add(u["severity"], f"{u['service']} ({u['port']}/udp) : {u['detail']}", u["ip"], "Services UDP")
        for d in ext["ipv6_parity"]:
            if d["v6_only"]:
                add("haute", "Ports ouverts en IPv6 seulement (filtrage IPv6 oublié) : " + _ints(d["v6_only"]),
                    f"{d['host']} {d['ipv6']}", "Parité IPv4 / IPv6")
        n = sum("password" in h["query"] for h in ext["github"])
        if n:
            add("moyenne", f"{n} fichier(s) de code public citant un domaine avec un mot de passe, secret ou jeton",
                "GitHub", "Code public (GitHub)")
    out.sort(key=lambda r: SEVERITY_RANK.get(r["severity"], 9))
    return out


def risks_section(risks):
    from .recon import _sev
    if not risks:
        return "<p><b>Top risques</b> : aucun constat critique, élevé ou moyen.</p>"
    merged, index = [], {}
    for r in risks:
        k = (r["severity"], r["title"])
        if k in index:
            if r["asset"] not in index[k]["assets"]:
                index[k]["assets"].append(r["asset"])
            continue
        index[k] = dict(r, assets=[r["asset"]])
        merged.append(index[k])
    count = Counter(m["severity"] for m in merged)
    out = [f'<details open class="risks"><summary><b>Top risques</b> - {count["critique"]} critique(s), '
           f'{count["haute"]} élevé(s), {count["moyenne"]} moyen(s)</summary><table><tr><th>Gravité</th>'
           f'<th>Constat</th><th>Concerne</th><th>Détail</th></tr>']
    for i, m in enumerate(merged):
        if i == 10:
            out.append(f'<tr><td colspan="4">… et {len(merged) - 10} autre(s) constat(s) dans les sections '
                       f'ci-dessous.</td></tr>')
            break
        assets = m["assets"]
        more = f" (+{len(assets) - 3})" if len(assets) > 3 else ""
        out.append(f"<tr><td>{_sev(m['severity'])}</td><td>{html.escape(m['title'])}</td>"
                   f"<td>{html.escape(', '.join(assets[:3]))}{more}</td><td>{html.escape(m['section'])}</td></tr>")
    out.append("</table></details>")
    return "".join(out)
