"""
core/enrich.py - Passive enrichment of the IPs behind the services found by netshot.

- reverse DNS (PTR) for every IP
- Shodan InternetDB (free, no key): open ports, CPEs, tags, known CVEs
- LeakIX (free key): indexed services and leaks
- CISA KEV and FIRST EPSS to rank the CVEs

Only public IPs are sent to third parties; internal addresses never leave the machine.
"""

import csv
import html
import ipaddress
import json
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from .sources import _get, get_json, is_internal_ip

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _resolve(host):
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        return sorted({i[4][0].split("%")[0] for i in socket.getaddrinfo(host, None)})
    except (socket.gaierror, UnicodeError, OSError):
        return []


def _ptr(ip):
    try:
        name, aliases, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        return []
    names = list(dict.fromkeys([name] + aliases))
    # The hosts file can map dozens of names to one address: keep the first few
    return names[:3] + ([f"+{len(names) - 3}"] if len(names) > 3 else [])


def _internetdb(e):
    status, body = _get(f"https://internetdb.shodan.io/{e['ip']}", 30)
    if status == 404:
        return  # nothing known
    if status != 200:
        raise RuntimeError(f"internetdb: HTTP {status}")
    res = json.loads(body)
    e["ports"], e["hostnames"] = res.get("ports", []), res.get("hostnames", [])
    e["tags"], e["cpes"] = res.get("tags", []), res.get("cpes", [])
    e["vulns"] = [{"cve": c, "kev": False, "epss": 0.0} for c in res.get("vulns", [])]


def _shodan_host(e, key):
    """Full Shodan host record (key): organisation, ASN, country, OS, product / version / page title
    seen on each port, CVEs. 404 'No information available' just means Shodan has not seen the IP."""
    status, body = _get(f"https://api.shodan.io/shodan/host/{e['ip']}?key={urllib.parse.quote(key)}", 30)
    if status == 404:
        return
    if status in (401, 403):
        raise RuntimeError(f"shodan: key refused (HTTP {status})")
    if status == 429:
        raise RuntimeError("shodan: rate limit reached")
    if status != 200:
        raise RuntimeError(f"shodan: HTTP {status}")
    res = json.loads(body)
    e["org"] = res.get("org") or res.get("isp") or ""
    e["asn"], e["country"], e["os"] = res.get("asn") or "", res.get("country_name") or "", res.get("os") or ""
    e["ports"], e["hostnames"], e["tags"] = res.get("ports", []), res.get("hostnames", []), res.get("tags", [])
    e["last_seen"] = (res.get("last_update") or "").split("T")[0]
    vulns = res.get("vulns") or []
    e["vulns"] = [{"cve": c, "kev": False, "epss": 0.0} for c in sorted(vulns)]  # list, or dict in old answers
    for d in res.get("data", []):
        svc = f"{d.get('port')}/{d.get('transport', 'tcp')}"
        http = d.get("http") or {}
        if d.get("product"):
            svc += " " + f"{d['product']} {d.get('version') or ''}".strip()
        elif http.get("server"):
            svc += " " + http["server"]
        if http.get("title"):
            svc += " - " + http["title"][:60]
        e["services"].append(svc)
        for c in d.get("cpe23") or []:
            if c not in e["cpes"]:
                e["cpes"].append(c)
    e["services"].sort()


def _leakix(e, key):
    status, body = _get(f"https://leakix.net/host/{e['ip']}", 30, {"api-key": key})
    if status == 404:
        return
    if status != 200:
        raise RuntimeError(f"leakix: HTTP {status}")
    res = json.loads(body) or {}
    e["leak_services"] = len(res.get("Services") or [])
    for leak in res.get("Leaks") or []:
        desc = str(leak.get("event_source", ""))
        if "port" in leak:
            desc += f" :{leak['port']}"
        sev = (leak.get("leak") or {}).get("severity")
        if sev:
            desc += f" ({sev})"
        e["leaks"].append(desc)


def _rank_vulns(exps, log):
    cves = sorted({v["cve"] for e in exps for v in e["vulns"]})
    if not cves:
        return
    kev = set()
    try:
        kev = {v["cveID"] for v in get_json("cisa-kev", KEV_URL).get("vulnerabilities", [])}
    except RuntimeError as exc:
        log(f"[enrich] {exc}")
    epss = {}
    for i in range(0, len(cves), 100):
        try:
            res = get_json("epss", "https://api.first.org/data/v1/epss?cve=" + ",".join(cves[i:i + 100]))
        except RuntimeError as exc:
            log(f"[enrich] {exc}")
            break
        epss.update({d["cve"]: float(d["epss"]) for d in res.get("data", [])})
    n_kev = 0
    for e in exps:
        for v in e["vulns"]:
            v["kev"], v["epss"] = v["cve"] in kev, epss.get(v["cve"], 0.0)
            n_kev += v["kev"]
        e["vulns"].sort(key=lambda v: (not v["kev"], -v["epss"]))
    log(f"[enrich] {len(cves)} distinct CVEs, {n_kev} occurrences in CISA KEV")


def kev_count(e):
    return sum(v["kev"] for v in e["vulns"])


def enrich(results, keys, log=print):
    """Look up every IP behind the scanned hosts. Returns a list of exposure dicts."""
    hosts = sorted({r["host"] for r in results})
    by_ip = {}
    with ThreadPoolExecutor(max_workers=16) as pool:
        for host, ips in zip(hosts, pool.map(_resolve, hosts)):
            for ip in ips:
                e = by_ip.setdefault(ip, {"ip": ip, "hosts": [], "ptr": [], "ports": [], "hostnames": [],
                                          "tags": [], "cpes": [], "vulns": [], "leak_services": 0,
                                          "leaks": [], "internal": is_internal_ip(ip), "notes": [],
                                          "org": "", "asn": "", "country": "", "os": "", "services": [],
                                          "last_seen": ""})
                if host != ip:
                    e["hosts"].append(host)
    exps = sorted(by_ip.values(), key=lambda e: ipaddress.ip_address(e["ip"]).packed.rjust(16, b"\0"))
    leak_key, shodan_key = keys.get("leakix", ""), keys.get("shodan", "")
    log(f"[enrich] {len(exps)} IPs ({sum(not e['internal'] for e in exps)} public): reverse DNS, "
        f"{'Shodan (clé)' if shodan_key else 'Shodan InternetDB'}{', LeakIX' if leak_key else ''}")

    def one(e):
        e["ptr"] = _ptr(e["ip"])
        if e["internal"]:
            return  # never send internal addresses to third parties
        def run(name, fn):
            try:
                fn()
                return True
            except Exception as exc:
                e["notes"].append(f"{name}: {exc}" if not str(exc).startswith(name) else str(exc))
                return False

        # Full Shodan host data with a key, else the free InternetDB summary
        if not (shodan_key and run("shodan", lambda: _shodan_host(e, shodan_key))):
            run("internetdb", lambda: _internetdb(e))
        if leak_key:
            run("leakix", lambda: _leakix(e, leak_key))

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(one, exps))
    _rank_vulns(exps, log)
    return exps


def write_exposure_csv(exps, outdir):
    with open(outdir / "exposure.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ip", "internal", "org", "asn", "country", "os", "hosts", "ptr", "shodan_ports",
                    "shodan_hostnames", "services", "tags", "cpes", "cves", "kev_cves", "max_epss",
                    "leakix_services", "leakix_leaks", "shodan_last_seen", "notes"])
        for e in exps:
            w.writerow([e["ip"], e["internal"], e["org"], e["asn"], e["country"], e["os"], " ".join(e["hosts"]),
                        " ".join(e["ptr"]), " ".join(map(str, e["ports"])), " ".join(e["hostnames"]),
                        "; ".join(e["services"]), " ".join(e["tags"]), " ".join(e["cpes"]),
                        " ".join(v["cve"] for v in e["vulns"]), " ".join(v["cve"] for v in e["vulns"] if v["kev"]),
                        f"{max((v['epss'] for v in e['vulns']), default=0):.4f}",
                        e["leak_services"], "; ".join(e["leaks"]), e["last_seen"], "; ".join(e["notes"])])


# --- HTML for report.html -------------------------------------------------------------

EXPOSURE_CSS = """
.exp{font-size:13px;color:#333;margin:0 0 8px}
.kev{background:#b00;color:#fff;border-radius:3px;padding:1px 5px;font-size:12px}
.cve{background:#eee;border-radius:3px;padding:1px 5px;font-size:12px}
table{border-collapse:collapse;background:#fff;font-size:13px;margin:8px 0 16px;width:100%}
th,td{border:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top}
th{background:#f0f0f0}
details{margin:8px 0}
"""


def vuln_badges(vulns, limit):
    """CVEs as badges: KEV ones in red, EPSS in the tooltip."""
    out = []
    for i, v in enumerate(vulns):
        if i == limit:
            out.append(f" +{len(vulns) - limit}")
            break
        cls, title = ("kev", "CISA KEV - ") if v["kev"] else ("cve", "")
        out.append(f' <span class="{cls}" title="{title}EPSS {v["epss"] * 100:.1f}%">{html.escape(v["cve"])}</span>')
    return "".join(out)


def exposure_line(e):
    """One-line summary shown under each host:port."""
    parts = [f"IP {html.escape(e['ip'])}"]
    if e["ptr"]:
        parts.append("PTR " + html.escape(", ".join(e["ptr"])))
    if e["internal"]:
        parts.append("interne")
    if e["org"]:
        parts.append(html.escape(e["org"]))
    if e["ports"]:
        parts.append("Shodan : ports " + ",".join(map(str, e["ports"])))
    if e["leak_services"] or e["leaks"]:
        parts.append(f"LeakIX : {e['leak_services']} services, {len(e['leaks'])} fuites")
    line = " · ".join(parts)
    if e["vulns"]:
        line += " ·" + vuln_badges(e["vulns"], 6)
    return f'<p class="exp">{line}</p>'


def exposure_table(exps):
    """Summary of every IP, most critical first."""
    if not exps:
        return ""
    ordered = sorted(exps, key=lambda e: (-kev_count(e), -(len(e["vulns"]) + len(e["leaks"]))))
    n_cve = sum(len(e["vulns"]) for e in exps)
    n_kev = sum(kev_count(e) for e in exps)
    rows = []
    for e in ordered:
        names = list(dict.fromkeys(n for n in e["hosts"] + e["ptr"] + e["hostnames"] if n))
        ip = html.escape(e["ip"]) + (" <i>(interne)</i>" if e["internal"] else "")
        leaks = (f"{e['leak_services']} services<br>{html.escape(', '.join(e['leaks']))}"
                 if e["leak_services"] or e["leaks"] else "")
        org = html.escape(" · ".join(x for x in dict.fromkeys([e["org"], e["asn"], e["country"]]) if x))
        if e["os"]:
            org += f"<br>OS : {html.escape(e['os'])}"
        if e["last_seen"]:
            org += f"<br><i>vu le {html.escape(e['last_seen'])}</i>"
        tech = "<br>".join(html.escape(x) for x in e["services"] + e["tags"] + e["cpes"])
        rows.append(f"<tr><td>{ip}</td><td>{org}</td><td>{html.escape(', '.join(names))}</td>"
                    f"<td>{', '.join(map(str, e['ports']))}</td><td>{tech}</td>"
                    f"<td>{vuln_badges(e['vulns'], 12)}</td><td>{leaks}</td></tr>")
    return (f"<details open><summary><b>Exposition (sources passives)</b> - {len(exps)} IP, {n_cve} CVE, "
            f"{n_kev} dans CISA KEV</summary><table><tr><th>IP</th><th>Organisation</th><th>Noms</th>"
            f"<th>Ports (Shodan)</th><th>Services / technologies</th><th>CVE</th><th>LeakIX</th></tr>{''.join(rows)}</table></details>")
