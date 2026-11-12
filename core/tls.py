"""
core/tls.py - TLS / certificate analysis of an endpoint, in the spirit of sslscan
(standard library only, same checks and grades as the Go version).

- protocol versions and cipher suites are probed with hand-built ClientHello messages, one
  suite at a time, so suites that OpenSSL refuses (RC4, EXPORT, NULL...) and SSLv3 are found;
- the post-quantum key exchange (X25519MLKEM768) is probed with a raw TLS 1.3 ClientHello that
  offers only that group without key share: a server that supports it asks for it (HRR);
- certificates are read from the raw TLS 1.2 handshake (or the ssl module) and decoded by a
  small DER parser; trust is checked with the ssl module against the system store.

    python -m core.tls example.com intranet:8443
"""

import csv
import hashlib
import html
import http.client
import ipaddress
import os
import socket
import ssl
import struct
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

PROTO_ORDER = ["SSLv3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"]
PROTO_VERSIONS = {"SSLv3": 0x0300, "TLS1.0": 0x0301, "TLS1.1": 0x0302, "TLS1.2": 0x0303, "TLS1.3": 0x0304}

# TLS 1.0-1.2 suites probed (IANA codes)
CIPHER_SUITES = [
    (0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"), (0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
    (0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"), (0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"),
    (0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"), (0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
    (0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"), (0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
    (0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"), (0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"),
    (0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"), (0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"), (0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"),
    (0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"), (0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
    (0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"), (0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
    (0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"), (0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
    (0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"), (0xC076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
    (0xC077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"), (0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"), (0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA"),
    (0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"), (0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
    (0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"), (0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM"),
    (0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM"), (0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
    (0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"), (0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
    (0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"), (0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"),
    (0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"), (0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"), (0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
    (0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"), (0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"),
    (0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"), (0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"),
    (0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"),
    (0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"), (0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
    (0xC09C, "TLS_RSA_WITH_AES_128_CCM"), (0xC09D, "TLS_RSA_WITH_AES_256_CCM"),
    (0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256"), (0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256"),
    (0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"), (0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
    (0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"), (0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"),
    (0x0096, "TLS_RSA_WITH_SEED_CBC_SHA"), (0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x0005, "TLS_RSA_WITH_RC4_128_SHA"), (0x0004, "TLS_RSA_WITH_RC4_128_MD5"),
    (0x0009, "TLS_RSA_WITH_DES_CBC_SHA"), (0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
    (0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"), (0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
    (0x003B, "TLS_RSA_WITH_NULL_SHA256"), (0x0002, "TLS_RSA_WITH_NULL_SHA"), (0x0001, "TLS_RSA_WITH_NULL_MD5"),
    (0xC004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"), (0xC005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"),
    (0xC00E, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"), (0xC00F, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"),
    (0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"), (0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA"),
    (0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"), (0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"),
    (0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"), (0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"),
]
TLS13_SUITES = [(0x1301, "TLS_AES_128_GCM_SHA256"), (0x1302, "TLS_AES_256_GCM_SHA384"),
                (0x1303, "TLS_CHACHA20_POLY1305_SHA256"), (0x1304, "TLS_AES_128_CCM_SHA256"),
                (0x1305, "TLS_AES_128_CCM_8_SHA256")]
SUITE_NAMES = dict(CIPHER_SUITES + TLS13_SUITES)
X25519MLKEM768 = 0x11EC


def cipher_strength(name):
    """insecure (broken), weak (no forward secrecy, CBC, 3DES...) or strong (AEAD + PFS, TLS 1.3)."""
    if any(k in name for k in ("NULL", "EXPORT", "anon", "RC4", "_DES_CBC", "DES40")) or name.endswith("MD5"):
        return "insecure"
    if "_WITH_" not in name:
        return "strong"  # TLS 1.3 suites
    if any(k in name for k in ("3DES", "_CBC_", "SEED", "DSS")) or name.startswith(("TLS_RSA_", "TLS_ECDH_")):
        return "weak"
    return "strong"


# --- Raw ClientHello probes -----------------------------------------------------------------

def _ext(typ, data):
    return struct.pack(">HH", typ, len(data)) + data


def client_hello(version, suites, sni, groups=None, key_share=True):
    """ClientHello record offering the given suites for one protocol version."""
    legacy = 0x0303 if version == 0x0304 else version
    body = struct.pack(">H", legacy) + os.urandom(32) + b"\0"
    cs = b"".join(struct.pack(">H", s) for s in suites)
    body += struct.pack(">H", len(cs)) + cs + b"\x01\x00"
    if version != 0x0300:
        exts = b""
        if sni:
            name = b"\0" + struct.pack(">H", len(sni)) + sni.encode("idna")
            exts += _ext(0, struct.pack(">H", len(name)) + name)
        g = b"".join(struct.pack(">H", x) for x in (groups or [29, 23, 24, 25, 256, 257]))
        exts += _ext(10, struct.pack(">H", len(g)) + g)
        exts += _ext(11, b"\x01\x00")
        sigs = b"".join(struct.pack(">H", x) for x in (0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
                                                        0x0401, 0x0501, 0x0601, 0x0203, 0x0201, 0x0807))
        exts += _ext(13, struct.pack(">H", len(sigs)) + sigs)
        exts += _ext(0xFF01, b"\0")
        exts += _ext(5, b"\x01\x00\x00\x00\x00")  # status_request: ask for a stapled OCSP answer
        if version == 0x0304:
            exts += _ext(43, b"\x02\x03\x04")
            exts += _ext(45, b"\x01\x01")
            share = struct.pack(">HH", 29, 32) + os.urandom(32) if key_share else b""
            exts += _ext(51, struct.pack(">H", len(share)) + share)
        body += struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16" + struct.pack(">HH", 0x0300 if version == 0x0300 else 0x0301, len(hs)) + hs


def _read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def probe(host, port, sni, version, suites, want_certs=False, groups=None, key_share=True):
    """Send a ClientHello; return the ServerHello info (dict) or None when refused."""
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except OSError:
        return None
    hello, buf = None, b""
    try:
        sock.settimeout(6)
        sock.sendall(client_hello(version, suites, sni, groups, key_share))
        for _ in range(64):
            hdr = _read_exact(sock, 5)
            payload = _read_exact(sock, struct.unpack(">H", hdr[3:5])[0])
            if hdr[0] != 22:  # alert or anything else: refusal / end
                return hello
            buf += payload
            while len(buf) >= 4:
                mlen = int.from_bytes(buf[1:4], "big")
                if len(buf) < 4 + mlen:
                    break
                typ, msg, buf = buf[0], buf[4:4 + mlen], buf[4 + mlen:]
                if typ == 2:  # ServerHello (or HelloRetryRequest)
                    sid = msg[34]
                    hello = {"version": struct.unpack(">H", msg[:2])[0],
                             "suite": struct.unpack(">H", msg[35 + sid:37 + sid])[0],
                             "certs": [], "ocsp": False, "group": None}
                    exts = msg[38 + sid:]
                    exts = exts[2:] if len(exts) >= 2 else b""
                    while len(exts) >= 4:
                        et, el = struct.unpack(">HH", exts[:4])
                        if et == 43 and el == 2:
                            hello["version"] = struct.unpack(">H", exts[4:6])[0]
                        if et == 51 and el >= 2:
                            hello["group"] = struct.unpack(">H", exts[4:6])[0]
                        exts = exts[4 + el:]
                    if not want_certs or hello["version"] >= 0x0304:
                        return hello
                elif typ == 11 and hello is not None:  # Certificate (TLS <= 1.2)
                    lst = msg[3:]
                    while len(lst) >= 3:
                        cl = int.from_bytes(lst[:3], "big")
                        hello["certs"].append(lst[3:3 + cl])
                        lst = lst[3 + cl:]
                elif typ == 22 and hello is not None:  # CertificateStatus: stapled OCSP
                    hello["ocsp"] = True
                elif typ == 14:  # ServerHelloDone
                    return hello
    except (OSError, ConnectionError, struct.error, IndexError):
        return hello
    finally:
        sock.close()
    return hello


def enumerate_suites(host, port, sni, version):
    """Accepted suites for one version, in server preference order; plus the first ServerHello."""
    remaining = [c for c, _ in (TLS13_SUITES if version == 0x0304 else CIPHER_SUITES)]
    found, first = [], None
    while remaining:
        sh = probe(host, port, sni, version, remaining, want_certs=first is None)
        if not sh or sh["version"] != version or sh["suite"] not in remaining:
            break
        first = first or sh
        name = SUITE_NAMES.get(sh["suite"], f"0x{sh['suite']:04X}")
        found.append({"name": name, "strength": cipher_strength(name)})
        remaining.remove(sh["suite"])
    return found, first


def pq_supported(host, port, sni):
    """Offer only X25519MLKEM768 without key share: a server that supports it answers with a
    HelloRetryRequest selecting it; other servers refuse."""
    sh = probe(host, port, sni, 0x0304, [c for c, _ in TLS13_SUITES], groups=[X25519MLKEM768], key_share=False)
    return bool(sh and sh["version"] == 0x0304 and sh["group"] == X25519MLKEM768)


# --- Minimal DER / X.509 decoder ----------------------------------------------------------------

def _tlv(b, i):
    tag, length = b[i], b[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(b[i:i + n], "big")
        i += n
    return tag, b[i:i + length], i + length


def _items(b):
    out, i = [], 0
    while i < len(b):
        tag, val, i = _tlv(b, i)
        out.append((tag, val))
    return out


def _oid(b):
    parts = [min(b[0] // 40, 2), b[0] - 40 * min(b[0] // 40, 2)]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


NAME_OIDS = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
             "1.2.840.113549.1.9.1": "E"}
SIG_OIDS = {"1.2.840.113549.1.1.11": "SHA256-RSA", "1.2.840.113549.1.1.12": "SHA384-RSA",
            "1.2.840.113549.1.1.13": "SHA512-RSA", "1.2.840.113549.1.1.5": "SHA1-RSA", "1.2.840.113549.1.1.4": "MD5-RSA",
            "1.2.840.113549.1.1.10": "RSASSA-PSS", "1.2.840.10045.4.3.2": "ECDSA-SHA256",
            "1.2.840.10045.4.3.3": "ECDSA-SHA384", "1.2.840.10045.4.3.4": "ECDSA-SHA512",
            "1.2.840.10045.4.1": "ECDSA-SHA1", "1.3.101.112": "Ed25519"}
CURVES = {"1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521"}


def _name(b):
    parts = []
    for _, rdn in _items(b):
        for _, atv in _items(rdn):
            (_, oid), (_, val) = _items(atv)[:2]
            parts.append(f"{NAME_OIDS.get(_oid(oid), _oid(oid))}={val.decode('utf-8', 'replace')}")
    return ",".join(reversed(parts))


def _time(tag, b):
    s = b.decode()
    fmt = "%y%m%d%H%M%SZ" if tag == 0x17 else "%Y%m%d%H%M%SZ"
    return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)


def _uris(b):
    """Every [6] URI (0x86) inside a DER blob."""
    out = []
    for tag, val in _items(b):
        if tag == 0x86:
            out.append(val.decode("ascii", "replace"))
        elif tag & 0x20:  # constructed: look inside
            out += _uris(val)
    return out


def parse_cert(der):
    """Decode the fields shown in the report from a DER certificate."""
    (_, cert), = _items(der)[:1]
    tbs = _items(_items(cert)[0][1])
    i = 1 if tbs[0][0] == 0xA0 else 0  # optional version
    serial = tbs[i][1]
    sig_oid = _oid(_items(tbs[i + 1][1])[0][1])
    issuer_raw, subject_raw = tbs[i + 2][1], tbs[i + 4][1]
    (t1, nb), (t2, na) = _items(tbs[i + 3][1])
    spki = _items(tbs[i + 5][1])
    alg = _items(spki[0][1])
    key_oid = _oid(alg[0][1])
    if key_oid == "1.2.840.113549.1.1.1":
        modulus = _items(_items(spki[1][1][1:])[0][1])[0][1]
        key = f"RSA {int.from_bytes(modulus, 'big').bit_length()} bits"
    elif key_oid == "1.2.840.10045.2.1":
        key = "ECDSA " + CURVES.get(_oid(alg[1][1]), _oid(alg[1][1]))
    elif key_oid == "1.3.101.112":
        key = "Ed25519"
    else:
        key = key_oid
    info = {"subject": _name(subject_raw), "issuer": _name(issuer_raw), "serial": serial.hex().upper().lstrip("0"),
            "sig_alg": SIG_OIDS.get(sig_oid, sig_oid), "key": key, "not_before_dt": _time(t1, nb),
            "not_after_dt": _time(t2, na), "sans": [], "ocsp_servers": [], "crls": [], "sct_embedded": False,
            "must_staple": False, "self_signed": issuer_raw == subject_raw}
    for tag, val in tbs[i + 6:]:
        if tag != 0xA3:
            continue
        for _, ext in _items(_items(val)[0][1]):
            parts = _items(ext)
            oid, value = _oid(parts[0][1]), parts[-1][1]
            if oid == "2.5.29.17":  # subjectAltName
                for gtag, gval in _items(_items(value)[0][1]):
                    if gtag == 0x82:
                        info["sans"].append(gval.decode("ascii", "replace"))
                    elif gtag == 0x87:
                        info["sans"].append(str(ipaddress.ip_address(gval)))
            elif oid == "1.3.6.1.5.5.7.1.1":  # authorityInfoAccess
                for _, ad in _items(_items(value)[0][1]):
                    m, loc = _items(ad)[:2]
                    if _oid(m[1]) == "1.3.6.1.5.5.7.48.1" and loc[0] == 0x86:
                        info["ocsp_servers"].append(loc[1].decode("ascii", "replace"))
            elif oid == "2.5.29.31":
                info["crls"] = _uris(value)
            elif oid == "1.3.6.1.4.1.11129.2.4.2":
                info["sct_embedded"] = True
            elif oid == "1.3.6.1.5.5.7.1.24":
                info["must_staple"] = True
    return info


def _cn(dn):
    for part in dn.split(","):
        if part.startswith("CN="):
            return part[3:]
    return dn


def name_matches(sans, host):
    host = host.lower().rstrip(".")
    for s in sans:
        s = s.lower()
        if s == host or (s.startswith("*.") and host.count(".") >= 2 and host.split(".", 1)[1] == s[2:]):
            return True
    return False


# --- Real handshakes (ssl module) -----------------------------------------------------------

def _context(verify=False):
    ctx = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.check_hostname = False  # the name is checked separately (name_matches)
    try:
        with warnings.catch_warnings():  # TLS 1.0 is deprecated, but we want to reach old servers
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


def default_handshake(host, port, sni):
    """Negotiated version/suite, ALPN and leaf certificate of a normal handshake."""
    ctx = _context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout=6) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni or None) as s:
            return {"negotiated": f"{s.version()} {s.cipher()[0]}", "alpn": s.selected_alpn_protocol() or "",
                    "leaf": s.getpeercert(binary_form=True)}


def check_trust(host, port, sni):
    """(trusted, error) against the system store (Windows store, so GPO-deployed CAs count)."""
    try:
        with socket.create_connection((host, port), timeout=6) as raw:
            with _context(verify=True).wrap_socket(raw, server_hostname=sni or None):
                return True, ""
    except ssl.SSLCertVerificationError as exc:
        return False, exc.verify_message or str(exc)
    except (OSError, ssl.SSLError) as exc:
        return False, f"vérification impossible ({exc})"


def read_hsts(host, port, sni):
    try:
        ctx = _context()
        ctx.set_alpn_protocols(["http/1.1"])
        conn = http.client.HTTPSConnection(host, port, timeout=6, context=ctx)
        conn.request("HEAD", "/", headers={"Host": sni or host, "User-Agent": "netshot"})
        value = conn.getresponse().getheader("Strict-Transport-Security", "")
        conn.close()
        return value or ""
    except (OSError, ssl.SSLError, http.client.HTTPException):
        return ""


# --- Analysis -------------------------------------------------------------------------------------

def parse_tls_targets(lines):
    """'host', 'host:port' or 'https://host:port/...' -> unique 'host:port' (default port 443)."""
    out = []
    for raw in lines:
        item = raw.split("#", 1)[0].strip()
        if not item:
            continue
        if "://" in item:
            item = item.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0]
        if item.startswith("["):
            host, _, rest = item[1:].partition("]")
            port = rest.lstrip(":") or "443"
        elif item.count(":") == 1:
            host, port = item.split(":")
        else:
            host, port = item, "443"
        t = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        if t not in out:
            out.append(t)
    return out


def analyze_tls(target):
    host, _, port = target.rpartition(":")
    host, port = host.strip("[]"), int(port)
    res = {"target": target, "host": host, "port": port, "ip": "", "sni": "", "error": "",
           "protocols": {}, "ciphers": {}, "cert": None, "negotiated": "", "key_group": "", "pq": False,
           "alpn": "", "hsts": "", "grade": "", "findings": []}
    try:
        ipaddress.ip_address(host)
    except ValueError:
        res["sni"] = host
    try:
        res["ip"] = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)[0][4][0]
    except OSError:
        pass

    # 1. Versions and suites
    firsts = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        for p, (ciphers, first) in zip(PROTO_ORDER, pool.map(
                lambda p: enumerate_suites(host, port, res["sni"], PROTO_VERSIONS[p]), PROTO_ORDER)):
            res["protocols"][p] = first is not None
            if ciphers:
                res["ciphers"][p] = ciphers
            firsts[p] = first
    raw_hello = next((firsts[p] for p in ("TLS1.2", "TLS1.1", "TLS1.0", "SSLv3") if firsts.get(p) and firsts[p]["certs"]), None)

    # 2. Default handshake, certificate
    chain, leaf = (raw_hello["certs"] if raw_hello else []), None
    try:
        hs = default_handshake(host, port, res["sni"])
        res["negotiated"], res["alpn"], leaf = hs["negotiated"], hs["alpn"], hs["leaf"]
    except (OSError, ssl.SSLError) as exc:
        if not any(res["protocols"].values()):
            res["error"], res["grade"] = f"pas de TLS sur ce port ({exc})", "-"
            return res
        res["negotiated"] = f"(handshake impossible avec OpenSSL : {exc})"
    if leaf and (not chain or chain[0] != leaf):
        chain = [leaf] + chain[1:]
    if chain:
        try:
            c = parse_cert(chain[0])
            trusted, err = check_trust(host, port, res["sni"])
            if not trusted and "Hostname mismatch" in err:
                trusted, err = True, ""
            now = datetime.now(timezone.utc)
            res["cert"] = {
                "subject": c["subject"], "issuer": c["issuer"], "sans": c["sans"],
                "not_before": c["not_before_dt"].strftime("%Y-%m-%d"), "not_after": c["not_after_dt"].strftime("%Y-%m-%d"),
                "days_left": int((c["not_after_dt"] - now).total_seconds() // 86400),
                "key": c["key"], "sig_alg": c["sig_alg"], "serial": c["serial"],
                "sha256": hashlib.sha256(chain[0]).hexdigest().upper(),
                "self_signed": c["self_signed"], "wildcard": any(s.startswith("*.") for s in c["sans"]),
                "trusted": trusted and c["not_after_dt"] > now, "trust_error": err,
                "name_match": not res["sni"] or name_matches(c["sans"], res["sni"]),
                "chain": [], "ocsp_stapled": bool(raw_hello and raw_hello["ocsp"]), "must_staple": c["must_staple"],
                "sct": c["sct_embedded"], "ocsp_servers": c["ocsp_servers"], "crls": c["crls"]}
            for der in chain:
                try:
                    p = parse_cert(der)
                    res["cert"]["chain"].append(f"{_cn(p['subject'])} ← {_cn(p['issuer'])}")
                except (ValueError, IndexError, UnicodeDecodeError):
                    pass
        except (ValueError, IndexError, UnicodeDecodeError) as exc:
            res["findings"].append(f"Certificat illisible : {exc}")

    # 3. Post-quantum key exchange, 4. HSTS
    res["pq"] = pq_supported(host, port, res["sni"])
    res["key_group"] = "X25519MLKEM768 accepté" if res["pq"] else ""
    res["hsts"] = read_hsts(host, port, res["sni"])
    res["grade"], res["findings"] = grade_tls(res, res["findings"])
    return res


def grade_tls(r, f):
    """Same grading as the Go version: F, T, C, B, A, A+."""
    rank = {"A+": 0, "A": 1, "B": 2, "C": 3, "T": 4, "F": 5}
    grade = "A"

    def worse(g):
        nonlocal grade
        if rank[g] > rank[grade]:
            grade = g

    p = r["protocols"]
    if p.get("SSLv3"):
        f.append("⚠ SSLv3 accepté (POODLE)")
        worse("F")
    old = [v for v in ("TLS1.0", "TLS1.1") if p.get(v)]
    if old:
        f.append("⚠ " + " et ".join(old) + " encore accepté(s) (obsolètes depuis 2021)")
        worse("C")
    if not p.get("TLS1.2") and not p.get("TLS1.3"):
        f.append("⚠ Ni TLS 1.2 ni TLS 1.3")
        worse("F")
    f.append("✓ TLS 1.3 disponible" if p.get("TLS1.3") else "Pas de TLS 1.3")
    f.append("✓ PQC : échange de clés post-quantique (X25519MLKEM768)" if r["pq"]
             else "Pas de PQC : échange de clés classique uniquement (pas de X25519MLKEM768)")
    names = {c["name"]: c["strength"] for lst in r["ciphers"].values() for c in lst}
    insecure = [n for n, s in names.items() if s == "insecure"]
    weak = [n for n, s in names.items() if s == "weak"]
    if insecure:
        f.append(f"⚠ {len(insecure)} suite(s) non sûre(s) : RC4, DES, EXPORT, NULL ou anonyme")
        worse("F")
    if weak:
        f.append(f"{len(weak)} suite(s) faible(s) (CBC, 3DES ou sans confidentialité persistante)")
        worse("B")
    if any(n.startswith("TLS_RSA_") for n in names):
        f.append("⚠ Échange de clés RSA accepté : pas de confidentialité persistante")
    c = r["cert"]
    if c:
        d = c["days_left"]
        if d < 0:
            f.append(f"⚠ Certificat EXPIRÉ depuis {-d} jours ({c['not_after']})")
            worse("F")
        elif d < 15:
            f.append(f"⚠ Expire dans {d} jours ({c['not_after']})")
        elif d < 30:
            f.append(f"Expire dans {d} jours ({c['not_after']})")
        if not c["trusted"]:
            f.append("⚠ Certificat auto-signé" if c["self_signed"] else "⚠ Certificat non reconnu par le magasin de confiance")
            worse("T")
        if not c["name_match"]:
            f.append(f"⚠ Le nom {r['sni']} n'est pas dans le certificat")
            worse("T")
        if c["key"].startswith("RSA ") and int(c["key"].split()[1]) < 2048:
            f.append(f"⚠ Clé RSA trop courte ({c['key']})")
            worse("F")
        if "SHA1" in c["sig_alg"] or "MD5" in c["sig_alg"]:
            f.append(f"⚠ Signature {c['sig_alg']} obsolète")
            worse("T")
        if not c["sct"] and c["trusted"] and not c["self_signed"]:
            f.append("Pas de preuve Certificate Transparency (SCT)")
        if c["must_staple"] and not c["ocsp_stapled"]:
            f.append("⚠ OCSP Must-Staple sans réponse OCSP agrafée")
    if r["hsts"]:
        f.append("✓ HSTS : " + r["hsts"])
        if grade == "A" and p.get("TLS1.3"):
            grade = "A+"
    else:
        f.append("Pas d'en-tête HSTS")
    return grade, f


def analyze_tls_all(targets, log=print, each=None):
    """Analyze several targets in parallel; log one line per target and call each(result)."""
    def run(t):
        start = datetime.now()
        try:
            r = analyze_tls(t)
        except Exception as exc:  # never let one endpoint stop the others
            r = {"target": t, "error": f"erreur d'analyse : {exc}", "grade": "-", "protocols": {}, "ciphers": {},
                 "cert": None, "findings": [], "pq": False, "hsts": "", "ip": "", "sni": "", "negotiated": "",
                 "key_group": "", "alpn": ""}
        secs = (datetime.now() - start).total_seconds()
        if log:
            if r["error"]:
                log(f"[tls] {t} : {r['error']}")
            else:
                days = f", expire dans {r['cert']['days_left']} j" if r["cert"] else ""
                log(f"[tls] {t} : note {r['grade']}{days} ({secs:.0f} s)")
        if each:
            each(r)
        return r

    with ThreadPoolExecutor(max_workers=6) as pool:
        return list(pool.map(run, targets))


def tls_targets_from_results(results):
    out = []
    for r in results:
        if r.get("file") and str(r.get("url", "")).startswith("https://"):
            t = f"{r['host']}:{r['port']}" if ":" not in r["host"] else f"[{r['host']}]:{r['port']}"
            if t not in out:
                out.append(t)
    return sorted(out)


# --- Output ------------------------------------------------------------------------------------

def proto_list(r):
    return " ".join(p for p in PROTO_ORDER if r["protocols"].get(p))


def format_tls(r):
    lines = [f"== {r['target']}  (IP {r['ip']}, SNI {r['sni']})  note {r['grade']}"]
    if r["error"]:
        return "\n".join(lines + [f"   {r['error']}", ""]) + "\n"
    lines += [f"   Protocoles   : {proto_list(r)}",
              f"   Négocié      : {r['negotiated']}  ALPN {r['alpn']}",
              f"   PQC (X25519MLKEM768) : {r['pq']}"]
    c = r["cert"]
    if c:
        lines += [f"   Certificat   : {c['subject']}", f"   Émetteur     : {c['issuer']}",
                  f"   Validité     : {c['not_before']} -> {c['not_after']} ({c['days_left']} jours restants)",
                  f"   Clé / sig.   : {c['key']} / {c['sig_alg']}", f"   SAN          : {', '.join(c['sans'])}",
                  f"   Confiance    : {c['trusted']}  nom OK {c['name_match']}  auto-signé {c['self_signed']}  "
                  f"OCSP agrafé {c['ocsp_stapled']}  SCT {c['sct']}"]
        lines += [f"   Chaîne       : {x}" for x in c["chain"]]
    for p in PROTO_ORDER:
        lines += [f"   {p:<7} {ci['strength']:<9} {ci['name']}" for ci in r["ciphers"].get(p, [])]
    lines += [f"   - {x}" for x in r["findings"]]
    return "\n".join(lines) + "\n\n"


def write_tls_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["target", "ip", "grade", "protocols", "pqc_mlkem", "negotiated", "alpn", "subject", "issuer", "sans",
                    "not_after", "days_left", "key", "signature", "trusted", "name_match", "self_signed",
                    "ocsp_stapled", "sct", "hsts", "weak_ciphers", "insecure_ciphers", "findings", "error"])
        for r in results:
            strengths = [c["strength"] for lst in r["ciphers"].values() for c in lst]
            c = r["cert"] or {}
            w.writerow([r["target"], r["ip"], r["grade"], proto_list(r), r["pq"], r["negotiated"], r["alpn"],
                        c.get("subject", ""), c.get("issuer", ""), " ".join(c.get("sans", [])), c.get("not_after", ""),
                        c.get("days_left", ""), c.get("key", ""), c.get("sig_alg", ""), c.get("trusted", ""),
                        c.get("name_match", ""), c.get("self_signed", ""), c.get("ocsp_stapled", ""), c.get("sct", ""),
                        r["hsts"], strengths.count("weak"), strengths.count("insecure"), " | ".join(r["findings"]),
                        r["error"]])


TLS_CSS = """
.ok{color:#15803d;font-weight:600}.no{color:#b91c1c;font-weight:600}.warnc{color:#c2410c;font-weight:600}
.grade{display:inline-block;min-width:28px;text-align:center;border-radius:4px;padding:1px 4px;color:#fff}
.gA{background:#15803d}.gB{background:#65a30d}.gC{background:#ca8a04}.gT{background:#c2410c}.gF{background:#b91c1c}
"""


def tls_section(results):
    """'Certificats et TLS' part of report.html."""
    if not results:
        return ""
    e = html.escape

    def yes(b):
        return '<span class="ok">oui</span>' if b else '<span class="no">non</span>'

    rows = []
    for r in results:
        if r["error"]:
            rows.append(f'<tr><td>{e(r["target"])}</td><td>-</td><td colspan="7">{e(r["error"])}</td></tr>')
            continue
        c = r["cert"]
        exp = key = issuer = trust = ""
        if c:
            cls = "no" if c["days_left"] < 0 else "warnc" if c["days_left"] < 30 else ""
            exp = f'<span class="{cls}">{e(c["not_after"])}<br>{c["days_left"]} j</span>'
            key, issuer, trust = f"{e(c['key'])}<br>{e(c['sig_alg'])}", e(c["issuer"]), yes(c["trusted"] and c["name_match"])
        protos = " ".join(f'<span class="{"no" if p in ("SSLv3", "TLS1.0", "TLS1.1") else "ok"}">{p}</span>'
                          for p in PROTO_ORDER if r["protocols"].get(p))
        finds = "<br>".join(e(x) for x in r["findings"] if x.startswith("⚠"))
        rows.append(f'<tr><td>{e(r["target"])}</td><td><b class="grade g{r["grade"].rstrip("+")}">{e(r["grade"])}</b></td>'
                    f"<td>{exp}</td><td>{protos}</td><td>{yes(r['pq'])}</td><td>{key}</td><td>{issuer}</td>"
                    f"<td>{trust}</td><td>{finds}</td></tr>")
    return (f"<details open><summary><b>Certificats et TLS</b> - {len(results)} point(s) d'accès</summary><table>"
            "<tr><th>Cible</th><th>Note</th><th>Expiration</th><th>Protocoles</th><th>PQC</th><th>Clé / signature</th>"
            f"<th>Émetteur</th><th>Confiance</th><th>Constats</th></tr>{''.join(rows)}</table></details>")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python -m core.tls host[:port] ...")
    for res in analyze_tls_all(parse_tls_targets(sys.argv[1:]), log=None):
        print(format_tls(res), end="")
