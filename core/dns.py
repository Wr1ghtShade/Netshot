"""
core/dns.py - A small DNS client (standard library only) to show what `dig` shows.

"ANY" queries are refused or answered with a single HINFO record by most modern servers
(RFC 8482), so the ANY answer is shown as is, then every common type is queried one by one.

    python -m core.dns example.com [server]
"""

import base64
import ipaddress
import os
import random
import socket
import struct
import sys
from concurrent.futures import ThreadPoolExecutor

TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 13: "HINFO", 15: "MX", 16: "TXT", 28: "AAAA",
         33: "SRV", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 99: "SPF",
         255: "ANY", 257: "CAA"}
TYPE_CODES = {v: k for k, v in TYPES.items()}

# Types asked on the domain itself, then well-known names below it
APEX_TYPES = ["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT", "CAA", "DS", "DNSKEY", "HTTPS"]
EXTRA_QUERIES = [
    ("www", "CNAME"), ("www", "A"),
    ("_dmarc", "TXT"), ("_mta-sts", "TXT"), ("_smtp._tls", "TXT"), ("default._bimi", "TXT"),
    ("_autodiscover._tcp", "SRV"), ("_sip._tls", "SRV"), ("_sipfederationtls._tcp", "SRV"),
    ("_ldap._tcp", "SRV"), ("_kerberos._tcp", "SRV"), ("_ldap._tcp.dc._msdcs", "SRV"), ("_gc._tcp", "SRV"),
    ("_xmpp-server._tcp", "SRV"), ("_caldavs._tcp", "SRV"),
]
RCODES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def system_dns_servers():
    """DNS servers of the machine: registry of the active interfaces on Windows, resolv.conf elsewhere."""
    servers = []
    if os.name == "nt":
        import winreg
        base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
        except OSError:
            return []
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                with winreg.OpenKey(root, sub) as k:
                    values = {}
                    for name in ("NameServer", "DhcpNameServer", "DhcpIPAddress", "IPAddress"):
                        try:
                            values[name] = winreg.QueryValueEx(k, name)[0]
                        except OSError:
                            pass
            except OSError:
                continue
            ip = values.get("DhcpIPAddress") or values.get("IPAddress")
            if isinstance(ip, list):
                ip = ip[0] if ip else ""
            if not ip or ip == "0.0.0.0":
                continue  # interface not connected
            for s in (values.get("NameServer") or values.get("DhcpNameServer") or "").replace(",", " ").split():
                if s not in servers:
                    servers.append(s)
    else:
        try:
            with open("/etc/resolv.conf") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        servers.append(parts[1])
        except OSError:
            pass
    return servers


# --- Wire format -----------------------------------------------------------------------

def build_query(name, qtype):
    qid = random.randrange(65536)
    msg = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)  # recursion desired, 1 question, 1 additional
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode()
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid name {name!r}")
        msg += bytes([len(raw)]) + raw
    msg += b"\0" + struct.pack(">HH", qtype, 1)
    # EDNS0 OPT record: 4096-byte UDP answers, so long TXT records fit
    msg += b"\0" + struct.pack(">HHIH", 41, 4096, 0, 0)
    return msg, qid


def _exchange(proto, server, port, query, timeout):
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    if proto == "udp":
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, (server, port))
            return s.recv(65535)
    with socket.create_connection((server, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(struct.pack(">H", len(query)) + query)
        data = b""
        while len(data) < 2 or len(data) < 2 + struct.unpack(">H", data[:2])[0]:
            chunk = s.recv(65535)
            if not chunk:
                raise OSError("connection closed")
            data += chunk
        return data[2:2 + struct.unpack(">H", data[:2])[0]]


def query(server, port, name, qtype, timeout=3.0):
    """One question; returns (records, rcode)."""
    q, qid = build_query(name, qtype)
    resp = _exchange("udp", server, port, q, timeout)
    # Retry over TCP when the UDP answer is truncated, or empty without error: some
    # resolvers (1.1.1.1) drop large answers (big TXT sets) without setting the TC flag.
    if len(resp) >= 12:
        flags, ancount = struct.unpack(">H", resp[2:4])[0], struct.unpack(">H", resp[6:8])[0]
        if flags & 0x0200 or (ancount == 0 and flags & 0x000F == 0):
            try:
                tresp = _exchange("tcp", server, port, q, timeout)
                if len(tresp) >= 12:
                    resp = tresp
            except OSError:
                pass
    if len(resp) < 12 or struct.unpack(">H", resp[:2])[0] != qid:
        raise OSError("invalid answer")
    try:
        return parse_answer(resp)
    except (struct.error, IndexError) as exc:  # truncated or malformed answer
        raise ValueError(f"malformed answer: {exc}") from exc


def read_name(msg, off):
    labels, end = [], None
    for _ in range(64):
        if off >= len(msg):
            raise ValueError("truncated name")
        n = msg[off]
        if n == 0:
            return ".".join(labels), (end if end is not None else off + 1)
        if n & 0xC0 == 0xC0:  # compression pointer
            if end is None:
                end = off + 2
            off = struct.unpack(">H", msg[off:off + 2])[0] & 0x3FFF
        else:
            labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
            off += 1 + n
    raise ValueError("name loop")


def parse_answer(msg):
    rcode = msg[3] & 0x0F
    qd, an = struct.unpack(">HH", msg[4:8])
    off = 12
    for _ in range(qd):
        off = read_name(msg, off)[1] + 4
    records = []
    for _ in range(an):
        name, off = read_name(msg, off)
        typ, _cls, ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        start = off + 10
        records.append({"name": name, "ttl": ttl, "type": TYPES.get(typ, f"TYPE{typ}"),
                        "data": rdata_string(msg, typ, start, rdlen)})
        off = start + rdlen
    return records, rcode


def _char_strings(b):
    out = []
    while b:
        n = b[0]
        out.append('"' + b[1:1 + n].decode("utf-8", "replace").replace('"', '\\"') + '"')
        b = b[1 + n:]
    return out


def rdata_string(msg, typ, start, n):
    """Record data rendered like dig does."""
    rd = msg[start:start + n]
    try:
        if typ in (1, 28):
            return str(ipaddress.ip_address(rd))
        if typ in (2, 5, 12):
            return read_name(msg, start)[0] + "."
        if typ == 15:
            return f"{struct.unpack('>H', rd[:2])[0]} {read_name(msg, start + 2)[0]}."
        if typ in (16, 99, 13):
            return " ".join(_char_strings(rd))
        if typ == 6:
            mname, o = read_name(msg, start)
            rname, o = read_name(msg, o)
            return f"{mname}. {rname}. " + " ".join(str(v) for v in struct.unpack(">IIIII", msg[o:o + 20]))
        if typ == 33:
            prio, weight, port = struct.unpack(">HHH", rd[:6])
            return f"{prio} {weight} {port} {read_name(msg, start + 6)[0]}."
        if typ == 257:
            tl = rd[1]
            return f'{rd[0]} {rd[2:2 + tl].decode()} "{rd[2 + tl:].decode("utf-8", "replace")}"'
        if typ == 43:
            return f"{struct.unpack('>H', rd[:2])[0]} {rd[2]} {rd[3]} {rd[4:].hex().upper()}"
        if typ == 48:
            key = base64.b64encode(rd[4:]).decode()
            return f"{struct.unpack('>H', rd[:2])[0]} {rd[2]} {rd[3]} {key[:40] + '…' if len(key) > 40 else key}"
        if typ in (64, 65):
            return _svcb_string(msg, start, n)
    except (ValueError, struct.error, IndexError, UnicodeDecodeError):
        pass
    return f"\\# {n} {rd.hex()}"


def _svcb_string(msg, start, n):
    """HTTPS / SVCB records: priority, target and the common parameters."""
    prio = struct.unpack(">H", msg[start:start + 2])[0]
    target, off = read_name(msg, start + 2)
    parts = [str(prio), (target + ".") if target else "."]
    end = start + n
    while off + 4 <= end:
        key, length = struct.unpack(">HH", msg[off:off + 4])
        v = msg[off + 4:min(off + 4 + length, end)]
        off += 4 + length
        if key == 1:
            alpn = []
            while v:
                alpn.append(v[1:1 + v[0]].decode())
                v = v[1 + v[0]:]
            parts.append("alpn=" + ",".join(alpn))
        elif key == 3 and len(v) == 2:
            parts.append(f"port={struct.unpack('>H', v)[0]}")
        elif key in (4, 6):
            size = 4 if key == 4 else 16
            ips = [str(ipaddress.ip_address(v[i:i + size])) for i in range(0, len(v) - size + 1, size)]
            parts.append(("ipv4hint=" if key == 4 else "ipv6hint=") + ",".join(ips))
        elif key == 5:
            parts.append("ech=…")
        else:
            parts.append(f"key{key}={v.hex()}")
    return " ".join(parts)


# --- Lookup ---------------------------------------------------------------------------

def _split_server(s):
    s = s.strip()
    if s.startswith("["):
        host, _, port = s[1:].partition("]")
        return host, int(port.lstrip(":") or 53)
    if s.count(":") == 1:
        host, port = s.split(":")
        return host, int(port)
    return s, 53


def dns_lookup(domain, server=""):
    """Every query against server ('' = system resolvers). Returns a report dict."""
    from .sources import normalize_domain
    domain = normalize_domain(domain)
    rep = {"domain": domain, "server": "", "any": [], "any_note": "", "records": [], "findings": [], "errors": []}
    servers = [server] if server else system_dns_servers()
    if not servers:
        servers = ["1.1.1.1"]
        rep["errors"].append("no system DNS server found, using 1.1.1.1")
    servers = [_split_server(s) for s in servers]

    def ask(name, qtype):
        last = None
        for host, port in servers:
            try:
                recs, rcode = query(host, port, name, TYPE_CODES[qtype] if isinstance(qtype, str) else qtype)
                return recs, rcode, f"{host}:{port}"
            except (OSError, ValueError) as exc:
                last = exc
        raise OSError(str(last) or "no answer")

    try:
        recs, rcode, rep["server"] = ask(domain, 255)
        if rcode:
            rep["any_note"] = f"ANY refusé par le serveur ({RCODES.get(rcode, rcode)})"
        elif not recs:
            rep["any_note"] = "ANY : réponse vide (refus RFC 8482)"
        elif len(recs) == 1 and recs[0]["type"] == "HINFO":
            rep["any_note"] = "ANY : réponse minimale HINFO (RFC 8482), détail par type ci-dessous"
        else:
            rep["any_note"] = f"ANY : {len(recs)} enregistrements"
        rep["any"] = recs
    except OSError as exc:
        rep["any_note"] = f"ANY : pas de réponse ({exc})"

    queries = [(domain, t) for t in APEX_TYPES] + [(f"{p}.{domain}", t) for p, t in EXTRA_QUERIES]

    def run(q):
        try:
            return q, ask(*q), None
        except OSError as exc:
            return q, None, exc

    seen = set()
    with ThreadPoolExecutor(max_workers=12) as pool:
        for (name, qtype), answer, err in pool.map(run, queries):
            if err:
                rep["errors"].append(f"{name} {qtype}: {err}")
                continue
            recs, rcode, _ = answer
            if rcode and rcode != 3:  # NXDOMAIN is a normal answer for optional names
                rep["errors"].append(f"{name} {qtype}: {RCODES.get(rcode, rcode)}")
            for r in recs:
                key = (r["name"], r["type"], r["data"])
                if key not in seen:
                    seen.add(key)
                    rep["records"].append(r)

    order = {t: i for i, t in enumerate(APEX_TYPES + ["SRV", "RRSIG"])}
    rep["records"].sort(key=lambda r: (r["name"] != domain, r["name"], order.get(r["type"], 99), r["data"]))
    rep["errors"].sort()
    rep["findings"] = dns_findings(domain, rep["records"])
    return rep


def dns_findings(domain, recs):
    """Mail, certificate and DNSSEC posture read from the records."""
    def txt(r):
        return r["data"].strip('"')
    spf = [txt(r) for r in recs if r["name"] == domain and r["type"] == "TXT" and txt(r).lower().startswith("v=spf1")]
    dmarc = [txt(r) for r in recs if r["name"] == "_dmarc." + domain and r["type"] == "TXT"
             and txt(r).lower().startswith("v=dmarc1")]
    has = lambda name, t: any(r["name"] == name and r["type"] == t for r in recs)  # noqa: E731
    mx = has(domain, "MX")
    f = []
    if not spf:
        f.append("⚠ Pas de SPF alors que le domaine reçoit du mail (MX)" if mx else "Pas de SPF")
    elif len(spf) > 1:
        f.append("⚠ Plusieurs enregistrements SPF : SPF invalide")
    elif "+all" in spf[0]:
        f.append("⚠ SPF en +all : n'importe quel serveur peut envoyer pour le domaine")
    elif "?all" in spf[0]:
        f.append("SPF neutre (?all) : peu protecteur")
    elif "~all" in spf[0]:
        f.append("SPF en ~all (softfail)")
    elif "-all" in spf[0]:
        f.append("✓ SPF strict (-all)")
    if not dmarc:
        f.append("⚠ Pas de DMARC")
    else:
        p = next((kv.split("=", 1)[1].strip().lower() for kv in dmarc[0].split(";")
                  if kv.strip().lower().startswith("p=")), "")
        if p in ("reject", "quarantine"):
            f.append(f"✓ DMARC p={p}")
        else:
            f.append(f"⚠ DMARC p={p} : surveillance seulement, aucun blocage")
    f.append("✓ CAA présent : autorités de certification limitées" if has(domain, "CAA")
             else "Pas de CAA : toute autorité de certification peut émettre")
    f.append("✓ DNSSEC actif (DS publié)" if has(domain, "DS") else "DNSSEC absent (pas de DS)")
    if any(r["name"] == "_mta-sts." + domain and r["type"] == "TXT" for r in recs):
        f.append("✓ MTA-STS publié")
    if any(r["type"] == "SRV" and (r["name"].startswith("_ldap._tcp.dc._msdcs.") or r["name"].startswith("_kerberos._tcp."))
           for r in recs):
        f.append("⚠ Enregistrements Active Directory visibles (_ldap / _kerberos)")
    return f


def dns_hosts(recs):
    """Host names and IPs found in the records (to add to the targets)."""
    out = []
    for r in recs:
        if r["type"] in ("A", "AAAA", "CNAME", "NS"):
            out.append(r["data"].rstrip("."))
        elif r["type"] == "MX" and len(r["data"].split()) == 2:
            out.append(r["data"].split()[1].rstrip("."))
        elif r["type"] == "SRV" and len(r["data"].split()) == 4:
            out.append(r["data"].split()[3].rstrip("."))
        if r["type"] in ("A", "AAAA"):
            out.append(r["name"])
    return [h for h in dict.fromkeys(out) if h]


def format_dig(rep):
    lines = [f"; netshot DNS {rep['domain']}  @{rep['server']}", f";; {rep['any_note']}"]
    lines += [f"{r['name']}.\t{r['ttl']}\tIN\t{r['type']}\t{r['data']}" for r in rep["any"]]
    lines += ["", ";; RECORDS (type by type)"]
    lines += [f"{r['name'] + '.':<40} {r['ttl']:>6} IN {r['type']:<7} {r['data']}" for r in rep["records"]]
    lines += ["", ";; FINDINGS"] + [f";  {x}" for x in rep["findings"]]
    if rep["errors"]:
        lines += ["", ";; ERRORS"] + [f";  {x}" for x in rep["errors"]]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python -m core.dns example.com [server]")
    print(format_dig(dns_lookup(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")), end="")
