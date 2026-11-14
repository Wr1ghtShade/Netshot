"""
core/export.py - results.json (everything the scan found) and results.xlsx (one sheet per topic,
filters and frozen header), written without any extra library.
"""

import json
import re
import zipfile
from datetime import datetime
from xml.sax.saxutils import escape

from . import __version__
from .recon import DEFAULT_CREDS
from .webinfo import TAGS, tech_label

_BAD_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_DROP = {"dup", "page_text"}  # report-only keys


def _clean(r):
    return {k: v for k, v in r.items() if k not in _DROP}


def write_json(path, results, exposures=None, tls_results=None, inventory=None, groups=None, takeovers=None,
               reputation=None):
    data = {
        "netshot_version": __version__,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "services": [_clean(r) for r in results],
        "technologies": inventory or [],
        "exposure": exposures or [],
        "tls": tls_results or [],
        "similar_pages": [[r["url"] for r in g] for g in groups or []],
        "takeovers": takeovers or [],
        "reputation": reputation or [],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1, default=str)


# --- Minimal xlsx writer ------------------------------------------------------------------------

def _col(n):
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _cell(ref, value, style=0):
    st = f' s="{style}"' if style else ""
    if isinstance(value, bool):
        return f'<c r="{ref}" t="b"{st}><v>{int(value)}</v></c>'
    if isinstance(value, (int, float)):
        return f'<c r="{ref}"{st}><v>{value}</v></c>'
    text = _BAD_XML.sub("", str(value if value is not None else ""))[:32000]
    if not text:
        return ""
    return f'<c r="{ref}" t="inlineStr"{st}><is><t xml:space="preserve">{escape(text)}</t></is></c>'


def _sheet(header, rows):
    widths = [len(str(h)) for h in header]
    for row in rows:
        for i, v in enumerate(row):
            widths[i] = max(widths[i], min(60, max((len(x) for x in str(v).split("\n")), default=0)))
    cols = "".join(f'<col min="{i}" max="{i}" width="{w + 2}" customWidth="1"/>'
                   for i, w in enumerate(widths, start=1))
    out = ['<row r="1">' + "".join(_cell(f"{_col(i)}1", h, 1) for i, h in enumerate(header, start=1)) + "</row>"]
    for n, row in enumerate(rows, start=2):
        out.append(f'<row r="{n}">' + "".join(_cell(f"{_col(i)}{n}", v, 2 if isinstance(v, str) and "\n" in v else 0)
                                             for i, v in enumerate(row, start=1)) + "</row>")
    last = f"{_col(len(header))}{max(1, len(rows) + 1)}"
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" '
            'state="frozen"/></sheetView></sheetViews>'
            f'<cols>{cols}</cols><sheetData>{"".join(out)}</sheetData>'
            f'<autoFilter ref="A1:{last}"/></worksheet>')


def write_xlsx(path, sheets):
    """sheets: [(name, header, rows)]; names up to 31 characters."""
    ct = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" '
          'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
          '<Override PartName="/xl/styles.xml" '
          'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>']
    wb_sheets, wb_rels = [], []
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for i, (name, header, rows) in enumerate(sheets, start=1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", _sheet(header, rows))
            ct.append(f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
                      'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
            wb_sheets.append(f'<sheet name="{escape(name[:31])}" sheetId="{i}" r:id="rId{i}"/>')
            wb_rels.append(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/'
                           f'2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>')
        n = len(sheets) + 1
        wb_rels.append(f'<Relationship Id="rId{n}" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                       'relationships/styles" Target="styles.xml"/>')
        z.writestr("[Content_Types].xml", "".join(ct) + "</Types>")
        z.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                   'relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        defined = "".join(f'<definedName name="_xlnm._FilterDatabase" localSheetId="{i}" hidden="1">'
                          f"'{escape(name[:31])}'!$A$1:${_col(len(h))}${max(1, len(r) + 1)}</definedName>"
                          for i, (name, h, r) in enumerate(sheets))
        z.writestr("xl/workbook.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                   f'<sheets>{"".join(wb_sheets)}</sheets><definedNames>{defined}</definedNames></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   f'{"".join(wb_rels)}</Relationships>')
        z.writestr("xl/styles.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                   '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
                   '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts>'
                   '<fills count="3"><fill><patternFill patternType="none"/></fill>'
                   '<fill><patternFill patternType="gray125"/></fill>'
                   '<fill><patternFill patternType="solid"><fgColor rgb="FF333333"/></patternFill></fill></fills>'
                   '<borders count="1"><border/></borders>'
                   '<cellStyleXfs count="1"><xf/></cellStyleXfs>'
                   '<cellXfs count="3"><xf/><xf fontId="1" fillId="2" applyFont="1" applyFill="1"/>'
                   '<xf applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf></cellXfs>'
                   '</styleSheet>')


def build_sheets(results, exposures=None, inventory=None, takeovers=None, reputation=None):
    services = [[r.get("host", ""), r.get("port", ""), r.get("ua", ""), r.get("url", ""),
                 r.get("status", ""), r.get("title", ""), r.get("final_url", ""),
                 " ".join(r.get("tags") or []), ", ".join(tech_label(t) for t in r.get("tech") or []),
                 r.get("favicon_hash", ""), r.get("group") or "", len(r.get("header_issues") or []),
                 r.get("file", ""), r.get("error", "")] for r in results]
    sheets = [("Services", ["Hôte", "Port", "UA", "URL", "Code HTTP", "Titre", "URL finale", "Repères",
                            "Technologies", "Favicon (hash)", "Groupe visuel", "Constats en-têtes",
                            "Capture", "Erreur"], services)]
    sensitive = [[t, TAGS[t], r["url"], r.get("status", ""), r.get("title", "")]
                 for r in results for t in r.get("tags") or [] if t in TAGS]
    sheets.append(("Pages sensibles", ["Repère", "Signification", "URL", "Code HTTP", "Titre"], sensitive))
    if inventory:
        rows = []
        for e in inventory:
            v = e.get("vulns") or []
            rows.append([e["name"], e["version"], len(e["urls"]), len(v), sum(x["kev"] for x in v),
                         round(max((x["epss"] for x in v), default=0), 4),
                         max((x.get("cvss", 0) for x in v), default=0),
                         " ".join(x["cve"] for x in v if x["kev"]), " ".join(x["cve"] for x in v),
                         DEFAULT_CREDS.get(e["name"], ""), "\n".join(e["urls"])])
        sheets.append(("Technologies", ["Technologie", "Version", "Services", "CVE", "CVE KEV", "EPSS max",
                                        "CVSS max", "Liste KEV", "Liste CVE", "Identifiants par défaut", "URL"], rows))
    issues, seen = [], set()
    for r in results:  # one line per URL and finding, whatever the number of user agents
        for i in r.get("header_issues") or []:
            if (r["url"], i) not in seen:
                seen.add((r["url"], i))
                issues.append([r["url"], i])
    sheets.append(("En-têtes", ["URL", "Constat"], issues))
    pc, seen_pc = [], set()
    for r in results:  # one line per page, whatever the number of user agents
        if not r.get("file") or r["url"] in seen_pc:
            continue
        seen_pc.add(r["url"])
        cols = [r.get(k) or [] for k in ("waf", "mixed_content", "no_sri", "trackers", "third_party_hosts")]
        if any(cols) or r.get("waf_probe"):
            pc.append([r["url"], ", ".join(cols[0]), r.get("waf_probe") or "", "\n".join(cols[1]), "\n".join(cols[2]),
                       "\n".join(cols[3]), " ".join(cols[4])])
    if pc:
        sheets.append(("WAF, SRI, traqueurs", ["URL", "WAF / CDN (passif)", "Test WAF actif", "Contenu mixte",
                                               "Sans SRI", "Traqueurs", "Hôtes tiers"], pc))
    if reputation:
        sheets.append(("Réputation", ["Niveau", "Nom / IP", "Bloqué par", "URLhaus", "Criminal IP", "Noms de l'IP",
                                       "Erreurs"],
                       [[x["level"], x["host"], ", ".join(x["blocked_by"]), x["urlhaus"], x.get("criminalip", ""),
                         ", ".join(x.get("names") or []), "; ".join(x["errors"])] for x in reputation]))
    files = [[f["severity"], f["url"], f["size"]] for r in results for f in r.get("files_found") or []]
    if files:
        sheets.append(("Fichiers exposés", ["Gravité", "URL", "Octets lus"], files))
    js_rows = []
    for r in results:
        js = r.get("js") or {}
        for sct in js.get("secrets") or []:
            js_rows.append([r["url"], "secret", sct["type"], sct["value"], sct["where"]])
        for u in js.get("internal_urls") or []:
            js_rows.append([r["url"], "URL interne", "", u, ""])
        for ep in js.get("endpoints") or []:
            js_rows.append([r["url"], "chemin d'API", "", ep, ""])
    if js_rows:
        sheets.append(("JavaScript", ["Page", "Type", "Détail", "Valeur (secrets masqués)", "Source:ligne"], js_rows))
    if takeovers:
        sheets.append(("Takeover", ["Gravité", "Nom", "Chaîne CNAME", "Service", "Raison"],
                       [[t["level"], t["host"], t["cname"], t["service"], t["reason"]] for t in takeovers]))
    svc = [[r["host"], r["port"], r.get("service", ""), r.get("service_version", ""), r.get("banner", ""),
            DEFAULT_CREDS.get(r.get("service") or "", "")]
           for r in results if (r.get("banner") or r.get("service")) and r.get("ua") in (None, "", "default")]
    if svc:
        sheets.append(("Services non web", ["Hôte", "Port", "Produit", "Version", "Bannière",
                                            "Identifiants par défaut"], svc))
    wk = []
    for r in results:
        w = r.get("well_known") or {}
        for path in w.get("robots") or []:
            wk.append([r["url"], "robots.txt", path])
        if w.get("sitemap_urls"):
            wk.append([r["url"], "sitemap", f"{w['sitemap_urls']} URL"])
        for k, v in (w.get("security") or {}).items():
            if k != "url":
                wk.append([r["url"], f"security.txt {k}", ", ".join(v)])
    if wk:
        sheets.append(("robots, sitemap", ["Service", "Source", "Valeur"], wk))
    if exposures:
        rows = [[e["ip"], e["internal"], e["org"], e["asn"], e["country"], " ".join(e["hosts"]),
                 " ".join(map(str, e["ports"])), "; ".join(e["services"]), len(e["vulns"]),
                 " ".join(v["cve"] for v in e["vulns"] if v["kev"]), " ".join(v["cve"] for v in e["vulns"]),
                 "; ".join(e["leaks"])] for e in exposures]
        sheets.append(("Exposition", ["IP", "Interne", "Organisation", "ASN", "Pays", "Noms", "Ports (Shodan)",
                                      "Services", "CVE", "CVE KEV", "Liste CVE", "LeakIX"], rows))
    return sheets
