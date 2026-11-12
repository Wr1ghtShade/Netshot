"""
core/whois.py - Who owns a domain, an IP address or an AS (standard library only).

Two sources, queried in parallel:
- RDAP (RFC 9082/9083): structured JSON over HTTPS, the server found through the IANA bootstrap
  files. Works through the system proxy. Used for the summary table and the findings.
- WHOIS (port 43): the classic text answer, following the IANA referral and, for thin registries
  such as .com, the registrar's own server. Often blocked by company firewalls: then only RDAP.

A subdomain (www.example.com) is looked up as its registered domain: RDAP is asked for the name
with one label less until a registry knows it.

    python -m core.whois example.com
    python -m core.whois 8.8.8.8
    python -m core.whois AS3215
"""

import ipaddress
import json
import re
import socket
import sys
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .sources import _get, normalize_domain

BOOTSTRAP = "https://data.iana.org/rdap/{}.json"
_bootstrap_cache = {}
ASN_RE = re.compile(r"^AS?(\d+)$", re.IGNORECASE)
REDACTED = re.compile(r"redact|privacy|not disclosed|withheld|data protected", re.IGNORECASE)

EVENT_LABELS = {"registration": "Création", "expiration": "Expiration", "last changed": "Dernière modification",
                "last update of RDAP database": "Mise à jour base RDAP", "transfer": "Dernier transfert"}
ROLE_LABELS = {"registrar": "Registrar", "registrant": "Titulaire", "administrative": "Contact admin",
               "technical": "Contact technique", "abuse": "Abuse", "noc": "NOC"}


# --- RDAP ------------------------------------------------------------------------------------

def _http_json(url, timeout=20):
    """(status, decoded JSON or None). Network errors raise OSError."""
    try:
        status, body = _get(url, timeout, {"Accept": "application/rdap+json, application/json"})
    except urllib.error.URLError as exc:
        raise OSError(str(exc.reason)) from None
    try:
        return status, json.loads(body)
    except ValueError:
        return status, None


def _bootstrap(kind):
    """IANA bootstrap services for 'dns', 'ipv4', 'ipv6' or 'asn' (cached for the session)."""
    if kind not in _bootstrap_cache:
        status, data = _http_json(BOOTSTRAP.format(kind))
        if status != 200 or not data:
            raise OSError(f"bootstrap IANA {kind}: HTTP {status}")
        _bootstrap_cache[kind] = data.get("services", [])
    return _bootstrap_cache[kind]


def _base(urls):
    url = next((u for u in urls if u.startswith("https://")), urls[0])
    return url if url.endswith("/") else url + "/"


def rdap_server(kind, query):
    """RDAP base URL for the query, or None when the registry has no RDAP service."""
    if kind == "domain":
        tld = query.rsplit(".", 1)[-1]
        for tlds, urls in _bootstrap("dns"):
            if tld in tlds:
                return _base(urls)
    elif kind == "ip":
        ip = ipaddress.ip_address(query)
        best = None
        for prefixes, urls in _bootstrap("ipv4" if ip.version == 4 else "ipv6"):
            for p in prefixes:
                net = ipaddress.ip_network(p, strict=False)
                if ip in net and (best is None or net.prefixlen > best[0]):
                    best = (net.prefixlen, _base(urls))
        return best[1] if best else None
    elif kind == "autnum":
        n = int(query)
        for ranges, urls in _bootstrap("asn"):
            for r in ranges:
                lo, _, hi = r.partition("-")
                if int(lo) <= n <= int(hi or lo):
                    return _base(urls)
    return None


def _vcard(entity):
    """{'fn', 'org', 'email', 'tel', 'country'} from a jCard."""
    out = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if len(item) < 4:
            continue
        name, params, value = item[0], item[1] or {}, item[3]
        if name in ("fn", "org", "email", "tel") and name not in out:
            out[name] = " ".join(map(str, value)) if isinstance(value, list) else str(value)
        elif name == "adr":
            if isinstance(value, list) and value and value[-1]:
                out["country"] = str(value[-1])
            elif params.get("cc"):
                out["country"] = params["cc"]
    return out


def _walk_entities(entities, found):
    """Flatten nested entities (the abuse contact sits inside the registrar) by role."""
    for e in entities or []:
        for role in e.get("roles", []):
            found.setdefault(role, []).append(e)
        _walk_entities(e.get("entities"), found)
    return found


def _date(s):
    return (s or "")[:10]


def _contact(e):
    v = _vcard(e)
    parts = [v.get("fn") or v.get("org") or e.get("handle", "")]
    if v.get("org") and v.get("org") != parts[0]:
        parts.append(v["org"])
    if v.get("country"):
        parts.append(v["country"])
    if v.get("email"):
        parts.append(v["email"])
    return " · ".join(p for p in parts if p)


def _summary(kind, data):
    """[(label, value)] rows from an RDAP object."""
    rows = []
    add = lambda label, value: value and (label, str(value)) not in rows and rows.append((label, str(value)))  # noqa: E731
    if kind == "domain":
        add("Domaine", (data.get("ldhName") or "").lower())
        add("Nom Unicode", data.get("unicodeName") if data.get("unicodeName") != data.get("ldhName") else "")
    elif kind == "ip":
        add("Plage", f"{data.get('startAddress', '')} - {data.get('endAddress', '')}")
        cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in data.get("cidr0_cidrs", [])]
        add("CIDR", ", ".join(cidrs))
        add("Nom du réseau", data.get("name"))
        add("Type", data.get("type"))
        add("Pays", data.get("country"))
        add("Réseau parent", data.get("parentHandle"))
    elif kind == "autnum":
        add("AS", f"AS{data.get('startAutnum')}" + (f"-AS{data['endAutnum']}" if data.get("endAutnum") not in
                                                     (None, data.get("startAutnum")) else ""))
        add("Nom", data.get("name"))
        add("Pays", data.get("country"))
    add("Identifiant (handle)", data.get("handle"))
    add("Statut", ", ".join(data.get("status", [])))
    for ev in data.get("events", []):
        label = EVENT_LABELS.get(ev.get("eventAction"))
        if label:
            add(label, _date(ev.get("eventDate")))
    roles = _walk_entities(data.get("entities"), {})
    for role in ("registrar", "registrant", "administrative", "technical", "abuse", "noc"):
        for e in roles.get(role, [])[:2]:
            value = _contact(e)
            if role == "registrar":
                ids = [p.get("identifier") for p in e.get("publicIds", []) if "IANA" in p.get("type", "")]
                value += f" (IANA {ids[0]})" if ids else ""
            add(ROLE_LABELS[role], value)
    if kind == "domain":
        add("Serveurs de noms", ", ".join((n.get("ldhName") or "").lower() for n in data.get("nameservers", [])))
        sec = data.get("secureDNS") or {}
        if "delegationSigned" in sec:
            add("DNSSEC", "signé" if sec["delegationSigned"] else "non signé")
    add("Serveur WHOIS", data.get("port43"))
    return rows


def _findings(kind, data):
    """Points worth a look: expiry, transfer lock, DNSSEC, hidden registrant."""
    f = []
    if kind != "domain":
        return f
    now = datetime.now(timezone.utc)
    for ev in data.get("events", []):
        if ev.get("eventAction") == "expiration" and ev.get("eventDate"):
            try:
                days = (datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00")) - now).days
            except ValueError:
                continue
            if days < 0:
                f.append(f"⚠ Domaine expiré depuis {-days} jours")
            elif days < 60:
                f.append(f"⚠ Expire dans {days} jours ({_date(ev['eventDate'])})")
            else:
                f.append(f"✓ Expire dans {days} jours ({_date(ev['eventDate'])})")
    status = {s.lower() for s in data.get("status", [])}
    if status:
        if any("transfer prohibited" in s for s in status):
            f.append("✓ Verrou de transfert actif (transfer prohibited)")
        else:
            f.append("⚠ Pas de verrou de transfert (clientTransferProhibited) : détournement du domaine plus facile")
        if any(s.startswith("server") for s in status):
            f.append("✓ Verrou au niveau du registre (server…Prohibited)")
    sec = data.get("secureDNS") or {}
    if "delegationSigned" in sec:
        f.append("✓ DNSSEC : délégation signée" if sec["delegationSigned"] else "⚠ DNSSEC : délégation non signée")
    roles = _walk_entities(data.get("entities"), {})
    reg = roles.get("registrant", [])
    if not reg or all(REDACTED.search(_contact(e) or "redacted") for e in reg):
        f.append("Titulaire masqué (RGPD / protection de la vie privée)")
    return f


def rdap_lookup(kind, query):
    """(kind, name actually found, url, data). Domains: strip labels until the registry knows one."""
    if kind == "domain":
        labels = query.split(".")
        base = rdap_server("domain", query)
        if not base:
            raise LookupError(f"pas de serveur RDAP pour .{labels[-1]}")
        last = None
        for i in range(len(labels) - 1):
            name = ".".join(labels[i:])
            url = f"{base}domain/{name}"
            status, data = _http_json(url)
            if status == 200 and data:
                return kind, name, url, data
            last = status
        raise LookupError(f"domaine inconnu du registre (HTTP {last})")
    base = rdap_server(kind, query)
    if not base:
        raise LookupError("pas de serveur RDAP pour cette ressource")
    url = f"{base}{'ip' if kind == 'ip' else 'autnum'}/{query}"
    status, data = _http_json(url)
    if status != 200 or not data:
        raise LookupError(f"HTTP {status}")
    return kind, query, url, data


# --- WHOIS port 43 -------------------------------------------------------------------------------

def whois43(server, query, timeout=10):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(query.encode("idna" if not query.isascii() else "ascii") + b"\r\n")
        chunks, size = [], 0
        while size < 1 << 20:
            chunk = s.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    # Servers answer with CRLF: keep plain newlines, or the copied text gets a blank line between each line
    return b"".join(chunks).decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")


def whois_text(query, server=""):
    """Classic WHOIS text: IANA referral, then the registry, then a thin registry's registrar."""
    if not server:
        iana = whois43("whois.iana.org", query)
        m = re.search(r"^(?:refer|whois):\s*(\S+)", iana, re.MULTILINE | re.IGNORECASE)
        if not m:
            return iana
        server = m.group(1)
    text = whois43(server, query)
    out = [f"% {server}", text.strip()]
    m = re.search(r"Registrar WHOIS Server:\s*(\S+)", text, re.IGNORECASE)
    if m:
        reg = m.group(1).lower().removeprefix("whois://").removeprefix("http://").removeprefix("https://").strip("/")
        if reg and reg != server.lower():
            try:
                out += ["", f"% {reg}", whois43(reg, query).strip()]
            except OSError as exc:
                out += ["", f"% {reg} : pas de réponse ({exc})"]
    return "\n".join(out) + "\n"


# --- Entry point ---------------------------------------------------------------------------------

def classify(raw):
    """('ip' | 'autnum' | 'domain', normalized query) or (None, '')."""
    raw = raw.strip()
    m = ASN_RE.match(raw)
    if m:
        return "autnum", m.group(1)
    try:
        return "ip", str(ipaddress.ip_address(raw.strip("[]")))
    except ValueError:
        pass
    d = normalize_domain(raw)
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return ("domain", d) if "." in d else (None, "")


def whois_lookup(raw):
    """Report dict: query, kind, name, rdap_url, rows [(label, value)], findings, raw, errors."""
    kind, query = classify(raw)
    rep = {"query": raw.strip(), "kind": kind, "name": f"AS{query}" if kind == "autnum" else query, "rdap_url": "", "rows": [], "findings": [],
           "raw": "", "errors": []}
    if not kind:
        rep["errors"].append("entrée non reconnue : domaine, IP ou AS1234 attendu")
        return rep
    whois_query = query if kind != "autnum" else f"AS{query}"

    def rdap():
        try:
            return rdap_lookup(kind, query), None
        except (OSError, LookupError, ValueError) as exc:
            return None, f"RDAP : {exc}"

    with ThreadPoolExecutor(max_workers=2) as pool:
        rdap_job = pool.submit(rdap)
        # For a subdomain, WHOIS needs the registered domain: wait for RDAP to name it
        found, err = rdap_job.result() if kind == "domain" else (None, None)
        if found:
            whois_query = found[1]
        whois_job = pool.submit(lambda q=whois_query: whois_text(q))
        if kind != "domain":
            found, err = rdap_job.result()
        try:
            rep["raw"] = whois_job.result()
        except (OSError, UnicodeError) as exc:
            rep["errors"].append(f"WHOIS (port 43) : {exc} - port 43 souvent filtré en entreprise")
    if err:
        rep["errors"].append(err)
    if found:
        _, rep["name"], rep["rdap_url"], data = found
        if kind == "autnum":
            rep["name"] = f"AS{query}"
        rep["rows"] = _summary(kind, data)
        rep["findings"] = _findings(kind, data)
    return rep


def format_whois(rep):
    lines = [f"; netshot WHOIS {rep['query']}" + (f"  ({rep['name']})" if rep["name"] and rep["name"] != rep["query"] else "")]
    if rep["rdap_url"]:
        lines.append(f";; RDAP {rep['rdap_url']}")
    width = max((len(k) for k, _ in rep["rows"]), default=0)
    lines += [f"{k:<{width}}  {v}" for k, v in rep["rows"]]
    if rep["findings"]:
        lines += ["", ";; FINDINGS"] + [f";  {x}" for x in rep["findings"]]
    if rep["errors"]:
        lines += ["", ";; ERRORS"] + [f";  {x}" for x in rep["errors"]]
    if rep["raw"]:
        lines += ["", ";; WHOIS (port 43)", rep["raw"].rstrip()]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python -m core.whois example.com | 8.8.8.8 | AS3215")
    print(format_whois(whois_lookup(sys.argv[1])), end="")
