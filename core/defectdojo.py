"""
core/defectdojo.py - DefectDojo export: defectdojo.json in the "Generic Findings Import" format, to
import in an engagement (Import Scan > Generic Findings Import, or POST /api/v2/import-scan/).
Same behaviour as defectdojo.go (netshot-go).

One finding per risk of the "Top risques" (discover.py), per CVE and IP, per CVE and technology, and
per sensitive file not already among the risks. unique_id_from_tool is stable from one scan to the
next, so a reimport closes what was fixed and keeps the history of what was not.
"""

import hashlib
import ipaddress
import json
from datetime import datetime
from urllib.parse import urlsplit

from . import __version__
from .discover import collect_risks

DD_SEVERITY = {"critique": "Critical", "haute": "High", "moyenne": "Medium", "basse": "Low", "info": "Info"}
RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def dd_id(*parts):
    return hashlib.sha1(("netshot\x00" + "\x00".join(parts)).encode()).hexdigest()[:20]


def dd_endpoint(asset):
    """"https://x/", "host:443", "203.0.113.5 (a.fr)" -> [endpoint] or []."""
    a = (asset or "").strip()
    for sep in (" ", "("):
        if sep in a:
            a = a[:a.index(sep)]
    if not a or "->" in a:
        return []
    u = urlsplit(a)
    if u.scheme and u.netloc:
        return [a]
    try:
        ip = ipaddress.ip_address(a.strip("[]"))
        if ip.version == 6:
            return [f"[{ip}]"]  # DefectDojo reads "//" + endpoint as a URL
    except ValueError:
        pass
    return [a] if any(c in a for c in ".:") else []


def cve_severity(v):
    """KEV first, then the CVSS score, then the EPSS; a CVE without score is Medium (to confirm)."""
    cvss, epss = v.get("cvss") or 0, v.get("epss") or 0
    if v.get("kev") or cvss >= 9:
        return "Critical"
    if cvss >= 7 or epss >= 0.5:
        return "High"
    if cvss >= 4 or cvss == 0:
        return "Medium"
    return "Low"


def vuln_facts(v):
    f = []
    if v.get("kev"):
        f.append("exploitée activement (catalogue CISA KEV)")
    if v.get("cvss"):
        f.append(f"CVSS {v['cvss']:.1f}")
    if v.get("epss"):
        f.append(f"EPSS {v['epss'] * 100:.1f} %")
    if not f:
        return ""
    s = ", ".join(f)
    return " " + s[0].upper() + s[1:] + "."


def build_defectdojo(results, exposures, tls_results, inventory, takeovers, reputation, cloud, ext, when=None):
    date = (when or datetime.now()).strftime("%Y-%m-%d")
    out, seen = [], set()

    def add(f):
        if f["unique_id_from_tool"] in seen:
            return
        seen.add(f["unique_id_from_tool"])
        f.update(date=date, active=True, verified=False, static_finding=False, dynamic_finding=True)
        if len(f["title"]) > 500:  # DefectDojo rejects a title over its column width
            f["title"] = f["title"][:497] + "…"
        f["endpoints"] = [e for x in f.get("endpoints") or [] for e in dd_endpoint(x)]
        out.append({k: v for k, v in f.items() if v not in (None, "", [])} | {"verified": False,
                                                                               "static_finding": False})
    # 1. CVEs, one finding per CVE and IP (InternetDB) or per CVE and technology (NVD)
    for x in exposures or []:
        hosts = [x["ip"]] + list(x.get("hosts") or [])
        for v in x.get("vulns") or []:
            add({"title": f"{v['cve']} sur {x['ip']}", "severity": cve_severity(v),
                 "description": f"{v['cve']} signalée sur {', '.join(hosts)} par Shodan InternetDB (version déduite des "
                                f"bannières : à confirmer).{vuln_facts(v)}",
                 "cve": v["cve"], "references": f"https://nvd.nist.gov/vuln/detail/{v['cve']}",
                 "unique_id_from_tool": dd_id("cve", v["cve"], x["ip"]), "vuln_id_from_tool": v["cve"],
                 "endpoints": hosts, "tags": ["netshot", "cve"]})
    for t in inventory or []:
        for v in t.get("vulns") or []:
            add({"title": f"{v['cve']} dans {t['name']} {t.get('version', '')}".strip(), "severity": cve_severity(v),
                 "description": f"{v['cve']} concerne {t['name']} {t.get('version', '')}, vu sur : "
                                f"{', '.join(t.get('urls') or [])}.{vuln_facts(v)}",
                 "cve": v["cve"], "references": f"https://nvd.nist.gov/vuln/detail/{v['cve']}",
                 "mitigation": f"Mettre à jour {t['name']}.",
                 "unique_id_from_tool": dd_id("tech", v["cve"], t["name"], t.get("version", "")),
                 "vuln_id_from_tool": v["cve"], "component_name": t["name"], "component_version": t.get("version", ""),
                 "endpoints": list(t.get("urls") or []), "tags": ["netshot", "cve"]})
    # 2. the other risks of the summary (CVE ones are above)
    for r in collect_risks(results, exposures, tls_results, takeovers, reputation, cloud, ext):
        if "CVE-" in r["title"]:
            continue
        add({"title": r["title"], "severity": DD_SEVERITY.get(r["severity"], "Info"),
             "description": f"{r['title']}\n\nConcerne : {r['asset']}\nDétail : section « {r['section']} » du rapport NetShot.",
             "unique_id_from_tool": dd_id("risk", r["title"], r["asset"]), "vuln_id_from_tool": r["section"],
             "endpoints": [r["asset"]], "tags": ["netshot", r["section"].lower().replace(" ", "-")]})
    # 3. sensitive files of lower severity (critical and high ones are risks)
    for r in results:
        for f in r.get("files_found") or []:
            if f["severity"] in ("critique", "haute"):
                continue
            add({"title": f"Fichier exposé : /{f['path']}", "severity": DD_SEVERITY.get(f["severity"], "Info"),
                 "description": f"{f['url']} répond ({f.get('size', 0)} octets).",
                 "unique_id_from_tool": dd_id("risk", f"Fichier sensible exposé : /{f['path']}", f["url"]),
                 "vuln_id_from_tool": "Fichiers sensibles", "endpoints": [f["url"]],
                 "tags": ["netshot", "fichiers-sensibles"]})
    out.sort(key=lambda f: RANK.get(f["severity"], 9))
    return out


def write_defectdojo(outdir, findings):
    doc = {"name": f"NetShot {datetime.now():%Y-%m-%d %H:%M}", "type": "NetShot", "version": __version__,
           "findings": findings}
    (outdir / "defectdojo.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
