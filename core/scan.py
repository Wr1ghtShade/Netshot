#!/usr/bin/env python3
"""
core/scan.py (run through netshot.py) - Screenshots of web services found on an internal network.

Targets: IP addresses, CIDR subnets (e.g. 10.0.0.0/24) or hostnames,
given on the command line and/or in a file (one target per line, '#' for comments).

For each host and port, the script:
  1. tests whether the TCP port is open (fast, no browser),
  2. opens http:// or https:// in headless Chromium,
  3. saves a PNG screenshot and records title + HTTP status.

Results: PNG files + report.html + results.csv in the output folder.

Install:
    pip install playwright
    python -m playwright install chromium

Examples:
    python netshot.py 192.168.1.0/24
    python netshot.py -f targets.txt -p 80,443,8080,8443 -o shots
    python netshot.py 10.0.0.5 10.0.1.0/28 -f more.txt --concurrency 20
    python netshot.py 10.0.0.0/24 --delay 2      # at most 1 page load every 2 s
    python netshot.py --ct example.com --ct-private          # hostnames from passive sources
    python netshot.py --ct example.com --ct-only > names.txt
    python netshot.py AS3215 -p 443                          # prefixes announced by an AS (RIPEstat)
    python netshot.py -f ad_computers.csv                    # CSV export: AD, ADCS, CMDB...
    python netshot.py --key domscan=XXXX --save-keys         # store a free API key
    python netshot.py --dns example.com [--dns-server 1.1.1.1]   # DNS records, like dig
    python netshot.py --whois example.com --whois 8.8.8.8 --whois AS3215   # owner (RDAP + WHOIS)
    python netshot.py --tls example.com --tls intranet:8443      # certificate and TLS setup, like sslscan
    python netshot.py 10.0.0.0/24 --tls-scan                     # scan, then analyze every https service

Passive sources, keys and IP enrichment live in core/sources.py and core/enrich.py.
Use only on networks and domains you are authorized to scan.
"""

import argparse
import asyncio
import base64
import csv
import html
import ipaddress
import re
import sys
from datetime import datetime
from pathlib import Path

from . import ASSETS, sources
from .enrich import EXPOSURE_CSS, enrich, exposure_line, exposure_table, write_exposure_csv
from .dns import dns_lookup, format_dig
from .whois import format_whois, whois_lookup
from .tls import (TLS_CSS, analyze_tls_all, format_tls, parse_tls_targets, tls_section,
                         tls_targets_from_results, write_tls_csv)
from .sources import (SUB_SOURCES, ct_lookup, expand_asns, import_targets, keys_path, load_keys,
                     resolve_source_names, update_keys)

# Imported lazily: passive lookups (--ct-only) and the GUI work without Playwright
try:
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None
PLAYWRIGHT_MISSING = "Playwright missing: pip install playwright && python -m playwright install chromium"

DEFAULT_PORTS = [80, 443, 8000, 8080, 8443]
HTTPS_PORTS = {443, 8443, 9443, 4443, 10443}
MAX_HOSTS_DEFAULT = 65536

# User agents to compare how sites react to different visitors.
# Only the User-Agent header changes: the page is still rendered by Chromium.
BROWSER_UAS = {
    "chrome-windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/130.0.0.0 Safari/537.36",
    "firefox-windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "edge-windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "safari-macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                    "Version/18.1 Safari/605.1.15",
    "chrome-android": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/130.0.0.0 Mobile Safari/537.36",
    "safari-iphone": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 "
                     "(KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
}
BOT_UAS = {
    "curl": "curl/8.10.1",
    "wget": "Wget/1.24.5",
    "python-requests": "python-requests/2.32.3",
    "python-urllib": "Python-urllib/3.12",
    "go-http": "Go-http-client/1.1",
    "powershell": "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.26100; en-US) PowerShell/7.4.6",
    "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "bingbot": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "nmap": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
}
USER_AGENTS = {**BROWSER_UAS, **BOT_UAS}


def resolve_user_agents(values):
    """Turn --ua values into [(name, ua_string)]. Accepts names, 'browsers', 'bots', 'all',
    or any other text as a literal User-Agent. Empty list = Chromium's own UA."""
    if not values:
        return [("default", None)]
    out = []
    custom = 0
    for v in values:
        v = v.strip()
        if v == "all":
            out += USER_AGENTS.items()
        elif v == "browsers":
            out += BROWSER_UAS.items()
        elif v == "bots":
            out += BOT_UAS.items()
        elif v == "default":
            out.append(("default", None))
        elif v in USER_AGENTS:
            out.append((v, USER_AGENTS[v]))
        elif v:
            custom += 1
            out.append((f"custom{custom}", v))
    seen = set()
    return [(n, ua) for n, ua in out if not (n in seen or seen.add(n))]


def parse_targets(items):
    """Expand IPs, CIDRs and hostnames into a list of unique hosts (order kept)."""
    hosts = []
    seen = set()
    for raw in items:
        item = raw.split("#", 1)[0].strip()
        if not item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
            # /31 and /32 have no network/broadcast address to skip
            addrs = list(net.hosts()) if net.num_addresses > 2 else list(net)
            for a in addrs:
                s = str(a)
                if s not in seen:
                    seen.add(s)
                    hosts.append(s)
        except ValueError:
            # Not an IP/CIDR: treat as hostname
            if item not in seen:
                seen.add(item)
                hosts.append(item)
    return hosts


def count_targets(items):
    total = 0
    for raw in items:
        item = raw.split("#", 1)[0].strip()
        if not item:
            continue
        try:
            total += ipaddress.ip_network(item, strict=False).num_addresses
        except ValueError:
            total += 1
    return total


def read_target_file(path):
    """Plain list (one target per line) or CSV export (AD, ADCS, CMDB...)."""
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        return import_targets(fh.read().splitlines())


def parse_ports(text):
    """Read "80,443,8000-8010". Raises ValueError on a malformed part."""
    ports = set()
    for part in text.split(","):
        part = part.strip()
        try:
            if "-" in part:
                lo, hi = part.split("-", 1)
                # Only 1-65535 is kept below: bound the range so "1-999999999" stays instant
                ports.update(range(max(int(lo), 1), min(int(hi), 65535) + 1))
            elif part:
                ports.add(int(part))
        except ValueError:
            raise ValueError(f"invalid port {part!r}") from None
    return sorted(p for p in ports if 0 < p < 65536)


async def port_open(host, port, timeout):
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9._-]", "_", text)


def build_url(host, port, scheme):
    h = f"[{host}]" if ":" in host else host  # IPv6
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{h}/" if default else f"{scheme}://{h}:{port}/"


# Banner drawn over the bottom of the page just before the screenshot, so every capture says where
# it comes from. Styles are set through element.style (allowed even under a strict CSP); the
# measures (title, size) are taken before, so the banner never changes them.
LABEL_JS = """(text) => {
  const d = document.createElement('div');
  d.id = '__netshot_label';
  const s = d.style;
  s.position = 'fixed'; s.left = '0'; s.right = '0'; s.bottom = '0'; s.zIndex = '2147483647';
  s.display = 'block'; s.margin = '0'; s.boxSizing = 'border-box'; s.padding = '6px 12px';
  s.background = 'rgba(17, 24, 39, 0.88)'; s.color = '#ffffff'; s.textAlign = 'left';
  s.font = 'bold 15px Consolas, "Courier New", monospace'; s.lineHeight = '1.4';
  s.whiteSpace = 'pre'; s.overflow = 'hidden'; s.textOverflow = 'ellipsis'; s.pointerEvents = 'none';
  d.textContent = text;
  (document.body || document.documentElement).appendChild(d);
}"""


def shot_label(host, port, url, final_url, status, ua_name):
    """Text of the banner: host:port, URL, redirect, HTTP status, user agent, date."""
    h = f"[{host}]" if ":" in host else host
    text = f"{h}:{port}   {url}"
    if final_url and final_url != url:
        text += f"  ->  {final_url}"
    if status:
        text += f"   [{status}]"
    if ua_name and ua_name != "default":
        text += f"   UA {ua_name}"
    return text + f"   {datetime.now():%Y-%m-%d %H:%M}"


async def capture(context, url, out_file, page_timeout, label=None):
    """label(final_url, status) -> banner text, or None for a capture without banner."""
    page = await context.new_page()
    try:
        # No HTTP cache: each user agent must get a fresh answer from the server
        try:
            cdp = await context.new_cdp_session(page)
            await cdp.send("Network.enable")
            await cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})
        except Exception:
            pass  # not Chromium: keep the cache
        resp = await page.goto(url, timeout=page_timeout * 1000, wait_until="load")
        await page.wait_for_timeout(800)  # let JS render a bit
        title = await page.title()
        size = len(await page.content())
        status = resp.status if resp else ""
        if label:
            try:
                await page.evaluate(LABEL_JS, label(page.url, status))
            except Exception:
                pass  # page navigated away or forbids scripts: capture without banner
        await page.screenshot(path=str(out_file), full_page=False)
        return {"status": status, "title": title, "final_url": page.url, "size": size, "error": ""}
    finally:
        await page.close()


class RateLimiter:
    """Guarantees at least `interval` seconds between two page loads, across all tasks."""

    def __init__(self, interval):
        self.interval = interval
        self.lock = asyncio.Lock()
        self.next_time = 0.0

    async def wait(self, stop=None):
        if self.interval <= 0:
            return
        async with self.lock:
            if stop and stop.is_set():
                return
            loop = asyncio.get_running_loop()
            delay = self.next_time - loop.time()
            if delay > 0:
                await asyncio.sleep(delay)
            self.next_time = loop.time() + self.interval


async def process(host, port, args, contexts, sem, results, counter, log, stop, limiter, on_shot):
    async with sem:
        if (stop and stop.is_set()) or not await port_open(host, port, args.connect_timeout):
            counter["done"] += 1
            return
        # Try the likely scheme first, fall back to the other one
        schemes = ["https", "http"] if port in HTTPS_PORTS else ["http", "https"]
        for ua_name, context in contexts:
            suffix = "" if ua_name == "default" else f"_{safe_name(ua_name)}"
            tag = "" if ua_name == "default" else f"  ({ua_name})"
            last_err = ""
            for scheme in schemes:
                url = build_url(host, port, scheme)
                out_file = args.output / f"{safe_name(host)}_{port}_{scheme}{suffix}.png"
                await limiter.wait(stop)
                if stop and stop.is_set():
                    break
                try:
                    label = None
                    if getattr(args, "label", True):
                        label = (lambda final, status, u=url, n=ua_name:
                                 shot_label(host, port, u, final, status, n))
                    info = await capture(context, url, out_file, args.page_timeout, label)
                    results.append({"host": host, "port": port, "ua": ua_name, "url": url,
                                    "file": out_file.name, **info})
                    log(f"[+] {url}  {info['status']}  {info['title'][:60]}{tag}")
                    if on_shot:
                        on_shot(str(out_file), url, info["status"], info["title"], ua_name)
                    break
                except Exception as exc:
                    err = str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__
                    last_err = f"{last_err} | {scheme}: {err}" if last_err else f"{scheme}: {err}"
            else:
                results.append({"host": host, "port": port, "ua": ua_name, "url": build_url(host, port, schemes[0]),
                                "file": "", "status": "", "title": "", "final_url": "", "size": "",
                                "error": last_err})
                log(f"[-] {host}:{port} open but no web page ({last_err[:160]}){tag}")
            if stop and stop.is_set():
                break
        counter["done"] += 1


def find_differences(group):
    """Return what changes between user agents for one host:port ([] = same answer)."""
    diffs = []
    for key, label in (("status", "status"), ("title", "title"), ("final_url", "redirect")):
        if len({str(r.get(key, "")) for r in group}) > 1:
            diffs.append(label)
    if len({bool(r.get("file")) for r in group}) > 1:
        diffs.append("capture failed")
    sizes = [r["size"] for r in group if isinstance(r.get("size"), int) and r["size"] > 0]
    if len(sizes) > 1 and (max(sizes) - min(sizes)) > 0.2 * max(sizes):
        diffs.append("page size")
    return diffs


def write_reports(results, outdir, exposures=None, tls_results=None):
    results.sort(key=lambda r: (r["host"], r["port"]))
    with open(outdir / "results.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["host", "port", "ua", "url", "status", "title", "final_url",
                                           "size", "file", "error"])
        w.writeheader()
        for r in results:
            w.writerow({k: r.get(k, "") for k in w.fieldnames})

    # One section per host:port, one card per user agent
    groups = {}
    for r in results:
        groups.setdefault((r["host"], r["port"]), []).append(r)
    multi_ua = any(len(g) > 1 for g in groups.values())

    # host (name or IP) -> exposures of its IPs
    by_host = {}
    for x in exposures or []:
        for h in [x["ip"]] + x["hosts"]:
            by_host.setdefault(h, []).append(x)

    sections = []
    n_diff = 0
    for (host, port), group in groups.items():
        diffs = find_differences(group) if len(group) > 1 else []
        n_diff += bool(diffs)
        cards = []
        for r in group:
            e = {k: html.escape(str(r.get(k, ""))) for k in r}
            img = (f'<a href="{e["file"]}"><img src="{e["file"]}" loading="lazy"></a>'
                   if r["file"] else f'<div class="err">{e["error"]}</div>')
            ua = f'<span class="ua">{e["ua"]}</span> ' if multi_ua else ""
            size = f' <span class="size">{int(r["size"]) // 1024} KB</span>' if r.get("size") else ""
            cards.append(
                f'<div class="card">{img}<div class="meta">{ua}'
                f'<a href="{e["url"]}">{e["url"]}</a><br>'
                f'<b>{e["status"]}</b> {e["title"]}{size}</div></div>'
            )
        badge = (f'<span class="diff">differs: {html.escape(", ".join(diffs))}</span>' if diffs else "")
        sections.append(
            f'<section class="{"has-diff" if diffs else "same"}"><h2>{html.escape(host)}:{port} {badge}</h2>'
            f'{"".join(exposure_line(x) for x in by_host.get(host, []))}'
            f'<div class="grid">{"".join(cards)}</div></section>'
        )

    filter_box = (f'<label><input type="checkbox" id="only"> only show the {n_diff} services that answer '
                  f'differently depending on the user agent</label>' if multi_ua else "")
    # The logo is embedded so the report stays a single self-contained file
    icon = ASSETS / "icon.png"
    logo = "data:image/png;base64," + base64.b64encode(icon.read_bytes()).decode() if icon.exists() else ""
    page = f"""<!doctype html><html><head><meta charset="utf-8"><title>NetShot - rapport</title>
<link rel="icon" type="image/png" href="{logo}">
<style>
body{{font-family:sans-serif;background:#f4f4f4;margin:16px}}
h2{{font-size:16px;margin:24px 0 8px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px}}
.card{{background:#fff;border:1px solid #ddd;border-radius:6px;overflow:hidden}}
.card img{{width:100%;display:block;border-bottom:1px solid #eee}}
.meta{{padding:8px;font-size:13px;word-break:break-all}}
.err{{padding:40px 8px;color:#a00;font-size:12px}}
.ua{{background:#246;color:#fff;border-radius:3px;padding:1px 6px;font-size:12px}}
.size{{color:#777}}
.diff{{background:#c60;color:#fff;border-radius:3px;padding:2px 8px;font-size:12px;font-weight:normal}}
body.only section.same{{display:none}}
{EXPOSURE_CSS}
{TLS_CSS}
h1.brand{{display:flex;align-items:center;gap:10px;margin:0 0 4px}}
h1.brand img{{width:36px;height:36px}}
</style></head><body>
<h1 class="brand">{f'<img src="{logo}" alt="">' if logo else ""}NetShot</h1><p>{len(groups)} services, {len(results)} captures - {datetime.now():%Y-%m-%d %H:%M}</p>
{exposure_table(exposures or [])}
{tls_section(tls_results or [])}
{filter_box}
{''.join(sections)}
<script>
var c=document.getElementById('only');
if(c)c.onchange=function(){{document.body.classList.toggle('only',c.checked)}};
</script></body></html>"""
    (outdir / "report.html").write_text(page, encoding="utf-8")


async def main_async(args, hosts, ports, log=print, stop=None, on_progress=None, on_shot=None, on_tls=None):
    """Run the scan. log: message callback, stop: threading.Event to abort,
    on_progress(done, total, found) and on_shot(png_path, url, status, title, ua_name):
    optional callbacks (used by the GUI)."""
    if async_playwright is None:
        raise RuntimeError(PLAYWRIGHT_MISSING)
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    counter = {"done": 0}
    total = len(hosts) * len(ports)
    sem = asyncio.Semaphore(args.concurrency)
    limiter = RateLimiter(getattr(args, "delay", 0))

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
        # One browser context per user agent
        contexts = []
        for ua_name, ua in getattr(args, "user_agents", None) or [("default", None)]:
            opts = {"ignore_https_errors": True, "viewport": {"width": args.width, "height": args.height}}
            if ua is not None:
                opts["user_agent"] = ua
            contexts.append((ua_name, await browser.new_context(**opts)))
        tasks = [process(h, p, args, contexts, sem, results, counter, log, stop, limiter, on_shot)
                 for h in hosts for p in ports]

        async def progress():
            while counter["done"] < total:
                if on_progress:
                    on_progress(counter["done"], total, len(results))
                    await asyncio.sleep(0.5)
                else:
                    await asyncio.sleep(5)
                    print(f"    ... {counter['done']}/{total} checked, {len(results)} found", file=sys.stderr)

        prog = asyncio.create_task(progress())
        await asyncio.gather(*tasks)
        prog.cancel()
        for _, context in contexts:
            await context.close()
        await browser.close()

    if on_progress:
        on_progress(total, total, len(results))
    exposures = None
    if getattr(args, "enrich", False) and results and not (stop and stop.is_set()):
        exposures = await asyncio.to_thread(enrich, results, getattr(args, "keys", None) or {}, log)
        write_exposure_csv(exposures, args.output)
    tls_results = None
    if getattr(args, "tls", False) and results and not (stop and stop.is_set()):
        targets = tls_targets_from_results(results)
        if targets:
            log(f"[tls] analyse de {len(targets)} service(s) https")
            tls_results = await asyncio.to_thread(analyze_tls_all, targets, log, on_tls)
            write_tls_csv(tls_results, args.output / "certificates.csv")
    write_reports(results, args.output, exposures, tls_results)
    ok = sum(1 for r in results if r["file"])
    log(f"\nDone: {ok} screenshots, {len(results) - ok} errors. Report: {args.output / 'report.html'}")
    return results


def main():
    ap = argparse.ArgumentParser(description="Screenshot web services on IPs / subnets.")
    ap.add_argument("targets", nargs="*", help="IP, CIDR (10.0.0.0/24), AS number (AS3215) or hostname")
    ap.add_argument("-f", "--file", action="append", default=[],
                    help="file with one target per line, or a CSV export (AD, ADCS, CMDB) (repeatable)")
    ap.add_argument("-p", "--ports", default=",".join(map(str, DEFAULT_PORTS)),
                    help="ports, e.g. 80,443,8000-8010 (default: %(default)s)")
    ap.add_argument("-o", "--output", type=Path, default=Path(f"screenshots_{datetime.now():%Y%m%d_%H%M%S}"))
    ap.add_argument("-c", "--concurrency", type=int, default=10, help="parallel checks (default: 10)")
    ap.add_argument("--connect-timeout", type=float, default=1.5, help="TCP timeout in seconds")
    ap.add_argument("--page-timeout", type=float, default=15, help="page load timeout in seconds")
    ap.add_argument("-d", "--delay", type=float, default=0,
                    help="minimum seconds between two page loads, e.g. 2 (default: 0 = no limit)")
    ap.add_argument("-u", "--ua", action="append", default=[],
                    help="user agent: a name from --list-ua, 'browsers', 'bots', 'all', or a literal "
                         "User-Agent string (repeatable; one capture per user agent)")
    ap.add_argument("--list-ua", action="store_true", help="list the built-in user agents and exit")
    ap.add_argument("--ct", action="append", default=[], metavar="DOMAIN",
                    help="domain to enumerate with passive sources (CT logs, passive DNS, archives); "
                         "found hostnames are added to the targets (repeatable)")
    ap.add_argument("--ct-sources", default="default",
                    help="'default', 'all', or a comma list among: " + ", ".join(s["name"] for s in SUB_SOURCES))
    ap.add_argument("--ct-key", default="", help="Cert Spotter API key (same as --key certspotter=...)")
    ap.add_argument("--ct-all", action="store_true", help="keep names even when they do not resolve in DNS")
    ap.add_argument("--ct-private", action="store_true", help="keep only names that resolve to a private IP")
    ap.add_argument("--ct-only", action="store_true", help="print the hostnames found and exit, without scanning")
    ap.add_argument("--list-sources", action="store_true", help="list the passive sources and configured keys, and exit")
    ap.add_argument("--key", action="append", default=[], metavar="SOURCE=KEY",
                    help="API key of a free service, e.g. domscan=abc (repeatable)")
    ap.add_argument("--save-keys", action="store_true", help=f"store the --key values in {keys_path()}")
    ap.add_argument("--no-label", action="store_true",
                    help="do not write host:port, URL, status and date at the bottom of the screenshots")
    ap.add_argument("--no-enrich", action="store_true",
                    help="do not enrich the IPs found (Shodan InternetDB, LeakIX, CISA KEV, EPSS)")
    ap.add_argument("--dns", metavar="DOMAIN",
                    help="show the DNS records of a domain (like dig: ANY, then type by type) and exit")
    ap.add_argument("--dns-server", default="",
                    help="DNS server for --dns, e.g. 1.1.1.1 or 10.0.0.1:53 (default: system resolvers)")
    ap.add_argument("--whois", action="append", default=[], metavar="DOMAIN|IP|ASN",
                    help="who owns a domain, an IP or an AS (RDAP + WHOIS port 43), then exit (repeatable)")
    ap.add_argument("--wordlist", metavar="FILE",
                    help="word list for the 'wordlist' source (DNS brute force), one label per line "
                         "(default: built-in 1,000 words)")
    ap.add_argument("--tls", action="append", default=[], metavar="HOST[:PORT]",
                    help="analyze the certificate and TLS setup of host[:port] (default port 443) and exit (repeatable)")
    ap.add_argument("--tls-scan", action="store_true",
                    help="after the scan, analyze the certificate and TLS setup of every https service found")
    ap.add_argument("--width", type=int, default=1920)
    ap.add_argument("--height", type=int, default=1080)
    ap.add_argument("--max-hosts", type=int, default=MAX_HOSTS_DEFAULT,
                    help="refuse above this many addresses (default: %(default)s)")
    args = ap.parse_args()

    if args.list_ua:
        for group, uas in (("browsers", BROWSER_UAS), ("bots", BOT_UAS)):
            print(f"[{group}]")
            for name, ua in uas.items():
                print(f"  {name:<16} {ua}")
        return
    args.user_agents = resolve_user_agents(args.ua)
    if args.dns:
        print(format_dig(dns_lookup(args.dns, args.dns_server)), end="")
        return
    if args.whois:
        for q in args.whois:
            print(format_whois(whois_lookup(q)))
        return
    if args.tls:
        for r in analyze_tls_all(parse_tls_targets(args.tls), log=None):
            print(format_tls(r), end="")
        return

    if args.wordlist:
        sources.custom_wordlist = read_target_file(args.wordlist)
    keys = load_keys()
    if args.ct_key:
        args.key.append(f"certspotter={args.ct_key}")
    typed = {}
    for kv in args.key:
        name, sep, value = kv.partition("=")
        if not sep:
            ap.error(f"--key expects SOURCE=KEY, got {kv!r}")
        keys[name.strip()] = typed[name.strip()] = value.strip()
    if args.save_keys:
        try:
            update_keys({k: v for k, v in typed.items() if v})  # only the --key values, merged on disk
        except (OSError, ValueError) as exc:
            ap.error(str(exc))
        print(f"keys saved to {keys_path()}", file=sys.stderr)
        if not (args.targets or args.file or args.ct):
            return
    if args.list_sources:
        print("Subdomain sources (--ct-sources):")
        for s in SUB_SOURCES:
            if s["key"] and keys.get(s["name"]):
                state = "key configured"
            elif s["key"] == "required":
                state = "KEY REQUIRED (free account)"
            elif s["key"] == "optional":
                state = "works without key, more with one"
            else:
                state = "no key needed"
            print(f"  {s['name']:<15} {state:<32} {s['help']}{' [default]' if s['default'] else ''}")
        print("\nEnrichment of the IPs found: Shodan host API (with key, else the free InternetDB), LeakIX (key), "
              "CISA KEV, FIRST EPSS.")
        print("Targets: AS<number> expands to the prefixes announced by the AS (RIPEstat).")
        print(f"Keys file: {keys_path()}")
        return
    args.keys = keys
    args.enrich = not args.no_enrich
    args.label = not args.no_label
    args.tls = args.tls_scan
    log_err = lambda m: print(m, file=sys.stderr)  # noqa: E731

    items = list(args.targets)
    for f in args.file:
        items += read_target_file(f)
    items = expand_asns(items, log=log_err)
    if args.ct:
        names = ct_lookup(args.ct, resolve_source_names(args.ct_sources.split(","), keys), keys,
                          resolve=not args.ct_all, private_only=args.ct_private, log=log_err)
        if args.ct_only:
            print("\n".join(names))
            return
        items += names
    if not items:
        ap.error("no target: give IP/CIDR on the command line or with -f file")

    n = count_targets(items)
    if n > args.max_hosts:
        sys.exit(f"{n} addresses > --max-hosts {args.max_hosts}. Narrow the range or raise --max-hosts.")

    if async_playwright is None:
        sys.exit(PLAYWRIGHT_MISSING)
    hosts = parse_targets(items)
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        ap.error(str(exc))
    print(f"{len(hosts)} hosts x {len(ports)} ports = {len(hosts) * len(ports)} checks")
    asyncio.run(main_async(args, hosts, ports))


if __name__ == "__main__":
    main()
