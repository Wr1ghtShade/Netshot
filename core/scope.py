"""
core/scope.py - Scope of a scan: exclusion list (targets outside the contract) and proxy.

Exclusions: IP, CIDR, host name, or *.domain (every sub-domain). A host name is also excluded
when one of its addresses falls in an excluded range, so a name cannot bring an excluded IP back.

Proxy: http://host:port (Burp, ZAP...) or socks5://host:port, with optional user:password@.
Pages, favicons and --dirs go through the proxy. The TCP port test goes through a SOCKS5 proxy
(pivot), and directly with an HTTP proxy (whose CONNECT answer says nothing about the port).
"""

import asyncio
import ipaddress
import socket
import struct
import urllib.parse
from concurrent.futures import ThreadPoolExecutor


# --- Exclusions ---------------------------------------------------------------------------

class Exclusions:
    def __init__(self, items=()):
        self.nets, self.names, self.suffixes = [], set(), []
        for raw in items:
            item = raw.split("#", 1)[0].strip().lower().rstrip(".")
            if not item:
                continue
            try:
                self.nets.append(ipaddress.ip_network(item, strict=False))
                continue
            except ValueError:
                pass
            if item.startswith("*."):
                self.suffixes.append(item[1:])  # ".example.com"
            else:
                self.names.add(item)

    def __bool__(self):
        return bool(self.nets or self.names or self.suffixes)

    def __len__(self):
        return len(self.nets) + len(self.names) + len(self.suffixes)

    def _ip_reason(self, ip):
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return ""
        for n in self.nets:
            if addr.version == n.version and addr in n:
                return f"{ip} dans {n}"
        return ""

    def reason(self, host, resolve=True):
        """Why host is out of scope, or "" when it is in scope."""
        h = host.strip().lower().rstrip(".").strip("[]")
        r = self._ip_reason(h)
        if r:
            return r
        try:
            ipaddress.ip_address(h)
            return ""  # an IP outside every excluded range
        except ValueError:
            pass
        if h in self.names:
            return f"{h} exclu"
        for s in self.suffixes:
            if h.endswith(s) or h == s[1:]:
                return f"{h} sous *{s}"
        if resolve and self.nets:
            try:
                ips = {i[4][0] for i in socket.getaddrinfo(h, None)}
            except (socket.gaierror, UnicodeError, OSError):
                ips = set()
            for ip in sorted(ips):
                r = self._ip_reason(ip)
                if r:
                    return f"{h} -> {r}"
        return ""

    def filter(self, hosts, log=print):
        """Keep the hosts in scope; log what was removed."""
        if not self:
            return list(hosts)
        with ThreadPoolExecutor(max_workers=32) as pool:
            reasons = list(pool.map(self.reason, hosts))
        kept = [h for h, r in zip(hosts, reasons) if not r]
        removed = [r for r in reasons if r]
        if removed:
            log(f"[exclusion] {len(removed)} cible(s) hors périmètre retirée(s)")
            for r in removed[:20]:
                log(f"    - {r}")
            if len(removed) > 20:
                log(f"    … +{len(removed) - 20}")
        return kept


def read_exclusions(values=(), files=()):
    """--exclude values (comma or space separated) + --exclude-file contents."""
    items = []
    for v in values:
        items += v.replace(",", " ").split()
    for f in files:
        with open(f, encoding="utf-8-sig", errors="replace") as fh:
            items += fh.read().splitlines()
    return Exclusions(items)


# --- Proxy ----------------------------------------------------------------------------------

def parse_proxy(url):
    """'http://user:pass@host:8080' -> dict, or None for ''. Raises ValueError when malformed."""
    url = (url or "").strip()
    if not url:
        return None
    if "://" not in url:
        url = "http://" + url
    u = urllib.parse.urlsplit(url)
    scheme = u.scheme.lower()
    if scheme == "socks5h":
        scheme = "socks5"
    if scheme not in ("http", "https", "socks5"):
        raise ValueError(f"proxy {url!r}: http://, https:// or socks5:// expected")
    if not u.hostname or not u.port:
        raise ValueError(f"proxy {url!r}: host:port expected, e.g. http://127.0.0.1:8080")
    if scheme == "socks5" and u.username:
        raise ValueError("Chromium does not support SOCKS5 with a password")
    host = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
    return {"scheme": scheme, "host": u.hostname, "port": u.port, "server": f"{scheme}://{host}:{u.port}",
            "username": urllib.parse.unquote(u.username or ""), "password": urllib.parse.unquote(u.password or "")}


def playwright_proxy(proxy):
    """Proxy dict for Playwright's launch() / new_context(), or None."""
    if not proxy:
        return None
    out = {"server": proxy["server"]}
    if proxy["username"]:
        out.update(username=proxy["username"], password=proxy["password"])
    return out


async def socks5_port_open(proxy, host, port, timeout):
    """TCP test through a SOCKS5 proxy: True when the proxy reaches host:port."""
    async def attempt():
        reader, writer = await asyncio.open_connection(proxy["host"], proxy["port"])
        try:
            writer.write(b"\x05\x01\x00")  # version 5, one method: no authentication
            await writer.drain()
            if await reader.readexactly(2) != b"\x05\x00":
                return False
            try:
                ip = ipaddress.ip_address(host.strip("[]"))
                addr = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
            except ValueError:
                name = host.encode("idna")
                addr = b"\x03" + bytes([len(name)]) + name
            writer.write(b"\x05\x01\x00" + addr + struct.pack(">H", port))
            await writer.drain()
            reply = await reader.readexactly(2)
            return reply[1] == 0
        finally:
            writer.close()

    try:
        return await asyncio.wait_for(attempt(), timeout)
    except Exception:
        return False
