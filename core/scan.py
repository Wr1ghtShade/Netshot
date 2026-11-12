#!/usr/bin/env python3
"""
core/scan.py (run through netshot.py) - Screenshots of web services found on an internal network.

Targets: IP addresses, CIDR subnets (e.g. 10.0.0.0/24) or hostnames,
given on the command line and/or in a file (one target per line, '#' for comments).

For each host and port, the script:
  1. tests whether the TCP port is open (fast, no browser),
  2. opens http:// or https:// in headless Chromium,
  3. saves a PNG screenshot and records title + HTTP status,
  4. reads what the page reveals (core/webinfo.py): technologies and versions, sensitive pages
     (Index of, login, admin, default page), security headers, favicon hash, similar pages.

Results: PNG files + report.html + results.csv + technologies.csv in the output folder.

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
import urllib.parse
from datetime import datetime
from pathlib import Path

from . import ASSETS, sources
from .enrich import EXPOSURE_CSS, enrich, exposure_line, exposure_table, write_exposure_csv
from .dns import dns_lookup, format_dig
from .whois import format_whois, whois_lookup
from .tls import (TLS_CSS, analyze_tls_all, format_tls, parse_tls_targets, tls_section,
                         tls_targets_from_results, write_tls_csv)
from .webinfo import (TAGS, WEB_CSS, card_extras, detect_tech, dir_words, probe_dirs, fetch_favicon, group_similar, groups_section,
                      header_issues, headers_section, lookup_tech_cves, page_tags, screenshot_phash,
                      sensitive_section, tech_inventory, tech_label, tech_section, write_tech_csv)
from .enrich import vuln_badges
from .export import build_sheets, write_json, write_xlsx
from .recon import (DEFAULT_CREDS, PORT_PRESETS, RECON_CSS, ScriptCollector, analyze_js, banner_display,
                    banners_section, check_takeover, file_rules, files_section, grab_banner, js_section,
                    parse_banner, probe_files, takeover_section, well_known, wellknown_section)
from .scope import Exclusions, parse_proxy, playwright_proxy, read_exclusions, socks5_port_open
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
        if part.lower() in PORT_PRESETS:
            ports.update(PORT_PRESETS[part.lower()])
            continue
        if part.lower() == "default":
            ports.update(DEFAULT_PORTS)
            continue
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


def _is_ip(text):
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
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


async def capture(context, url, out_file, page_timeout, label=None, web=None):
    """label(final_url, status) -> banner text, or None for a capture without banner.
    web: {"hasher": blank page, "favicons": cache} to analyse the page (technologies, sensitive
    page, headers, favicon, visual hash), or None."""
    page = await context.new_page()
    try:
        # No HTTP cache: each user agent must get a fresh answer from the server
        try:
            cdp = await context.new_cdp_session(page)
            await cdp.send("Network.enable")
            await cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})
        except Exception:
            pass  # not Chromium: keep the cache
        scripts = ScriptCollector(page) if web is not None else None
        resp = await page.goto(url, timeout=page_timeout * 1000, wait_until="load")
        await page.wait_for_timeout(800)  # let JS render a bit
        title = await page.title()
        content = await page.content()
        size = len(content)
        status = resp.status if resp else ""
        final_url = page.url
        info = {"status": status, "title": title, "final_url": final_url, "size": size, "error": ""}
        if web is not None:
            try:
                headers = await resp.headers_array() if resp else []
            except Exception:
                headers = []
            tech = detect_tech(headers, content, title)
            info.update(tech=tech, tags=page_tags(title, content, final_url, status, headers, tech),
                        header_issues=header_issues(final_url, headers, content))
            info["favicon_url"], info["favicon_hash"] = await fetch_favicon(page, context, page_timeout,
                                                                             web["favicons"])
            info["js"] = analyze_js(await scripts.sources(final_url, content))
            info["page_text"] = content[:20000]  # for the takeover fingerprints, not exported
        if label:
            try:
                await page.evaluate(LABEL_JS, label(final_url, status))
            except Exception:
                pass  # page navigated away or forbids scripts: capture without banner
        png = await page.screenshot(path=str(out_file), full_page=False)
        if web is not None:
            info["phash"] = await screenshot_phash(web["hasher"], png)
        return info
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
        proxy = getattr(args, "proxy", None)
        if proxy and proxy["scheme"] == "socks5":
            is_open = await socks5_port_open(proxy, host, port, args.connect_timeout + 2)
        else:
            is_open = await port_open(host, port, args.connect_timeout)
        if (stop and stop.is_set()) or not is_open:
            counter["done"] += 1
            return
        # Try the likely scheme first, fall back to the other one
        schemes = ["https", "http"] if port in HTTPS_PORTS else ["http", "https"]
        base_url = ""  # first URL that answered, for --dirs
        first_row = None
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
                    info = await capture(context, url, out_file, args.page_timeout, label,
                                         getattr(args, "web", None))
                    row = {"host": host, "port": port, "ua": ua_name, "url": url, "file": out_file.name, **info}
                    results.append(row)
                    first_row = first_row or row
                    extra = ""
                    if info.get("tags"):
                        extra += "  [" + ", ".join(info["tags"]) + "]"
                    if info.get("tech"):
                        extra += "  " + ", ".join(tech_label(t) for t in info["tech"][:4])
                    log(f"[+] {url}  {info['status']}  {info['title'][:60]}{tag}{extra}")
                    if on_shot:
                        on_shot(str(out_file), url, info["status"], info["title"], ua_name)
                    base_url = base_url or url
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
        web = getattr(args, "web", None)
        if first_row and web is not None and not (stop and stop.is_set()):
            first_row["well_known"] = await well_known(contexts[0][1], base_url, args.page_timeout)
            if first_row["well_known"].get("robots"):
                log(f"[robots] {base_url}robots.txt : {len(first_row['well_known']['robots'])} chemin(s)")
        if first_row and getattr(args, "files", None) and not (stop and stop.is_set()):
            found = await probe_files(contexts[0][1], base_url, args.files, args.page_timeout, limiter, stop)
            first_row["files_found"] = found
            for f in found:
                log(f"[fichier] {f['url']}  {f['severity']}")
        if not first_row and web is not None and not (stop and stop.is_set()):
            await identify_service(host, port, args, results, log)
        if base_url and getattr(args, "dirs", None) and not (stop and stop.is_set()):
            await probe_service_dirs(host, port, base_url, args, contexts[0][1], results, log, stop,
                                     limiter, on_shot)
        counter["done"] += 1


async def identify_service(host, port, args, results, log):
    """Open port without a web page: read its banner (SSH, FTP, SMTP, MySQL, Redis, RDP...)."""
    text = await grab_banner(host, port, proxy=getattr(args, "proxy", None))
    name, version, cpes = parse_banner(text)
    if not (text or name):
        return
    for r in results:
        if r["host"] == host and r["port"] == port and not r.get("file"):
            r["banner"], r["service"], r["service_version"] = banner_display(text), name, version
            if name:
                r["tech"] = [{"name": name, "version": version, "cpes": cpes, "admin": False}]
    log(f"[service] {host}:{port}  {name or '?'} {version}  {banner_display(text)[:80]}")


async def probe_service_dirs(host, port, base_url, args, context, results, log, stop, limiter, on_shot):
    """--dirs: test the common folders, capture each directory listing found."""
    found = await probe_dirs(context, base_url, args.dirs, args.page_timeout, limiter, stop)
    for url in found:
        if stop and stop.is_set():
            return
        path = urllib.parse.urlsplit(url).path.strip("/")
        scheme = urllib.parse.urlsplit(url).scheme
        out_file = args.output / f"{safe_name(host)}_{port}_{scheme}_dir_{safe_name(path)}.png"
        label = None
        if getattr(args, "label", True):
            label = lambda final, status, u=url: shot_label(host, port, u, final, status, "default")
        try:
            info = await capture(context, url, out_file, args.page_timeout, label, getattr(args, "web", None))
        except Exception as exc:
            log(f"[dir] {url}  liste de fichiers, capture impossible ({str(exc).splitlines()[0][:120]})")
            continue
        tags = info.get("tags") or []
        if "index-of" not in tags:
            info["tags"] = ["index-of"] + tags
        results.append({"host": host, "port": port, "ua": "dossier", "dir": True, "url": url,
                        "file": out_file.name, **info})
        log(f"[dir] {url}  {info['status']}  Index of : liste de fichiers")
        if on_shot:
            on_shot(str(out_file), url, info["status"], info["title"], "dossier")


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


FILTER_CSS = """
.filters{position:sticky;top:0;z-index:5;background:#f4f4f4;padding:8px 0;border-bottom:1px solid #ddd;
  display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:13px}
.filters input[type=search]{width:280px;padding:4px}.filters select{padding:3px}
.card.f-hide,section.f-hide{display:none}
#fcount{color:#555}
"""
FILTER_JS = r"""
(function(){
  var q=document.getElementById('fq'),s=document.getElementById('fstatus'),t=document.getElementById('ftag'),
      e=document.getElementById('ftech'),n=document.getElementById('fcount'),r=document.getElementById('freset');
  if(!q)return;
  function apply(){
    var text=q.value.toLowerCase().trim().split(/\s+/).filter(Boolean),shown=0,total=0;
    document.querySelectorAll('section').forEach(function(sec){
      var any=false;
      sec.querySelectorAll('.card').forEach(function(c){
        total++;
        var ok=(!s.value||c.dataset.status===s.value)
          &&(!t.value||(t.value==='none'?!c.dataset.tags:(' '+c.dataset.tags+' ').indexOf(' '+t.value+' ')>=0))
          &&(!e.value||('|'+c.dataset.tech+'|').indexOf('|'+e.value+'|')>=0)
          &&text.every(function(w){return c.dataset.q.indexOf(w)>=0});
        c.classList.toggle('f-hide',!ok);if(ok){any=true;shown++}
      });
      sec.classList.toggle('f-hide',!any);
    });
    n.textContent=shown+' / '+total+' captures';
  }
  [q,s,t,e].forEach(function(x){x.addEventListener('input',apply)});
  r.onclick=function(){q.value='';s.value='';t.value='';e.value='';apply()};
  apply();
})();
"""


def filter_bar(results, inventory):
    """Search box and drop-down filters over the capture cards."""
    statuses = sorted({(f"{str(r.get('status'))[0]}xx" if str(r.get("status") or "")[:1] in "12345"
                        and r.get("status") else "err") for r in results})
    tags = [t for t in TAGS if any(t in (r.get("tags") or []) for r in results)]
    techs = sorted({t["name"] for r in results for t in r.get("tech") or []}, key=str.lower)
    opt = lambda v, label: f'<option value="{html.escape(v)}">{html.escape(label)}</option>'  # noqa: E731
    return ('<div class="filters"><input type="search" id="fq" placeholder="Rechercher (URL, titre, techno, tag…)">'
            '<select id="fstatus"><option value="">Tous les codes</option>'
            + "".join(opt(x, "Erreur / pas de page" if x == "err" else x) for x in statuses) + "</select>"
            '<select id="ftag"><option value="">Tous les repères</option>'
            + "".join(opt(x, f"{x} - {TAGS[x]}") for x in tags) + opt("none", "sans repère") + "</select>"
            '<select id="ftech"><option value="">Toutes les technologies</option>'
            + "".join(opt(x, x) for x in techs) + "</select>"
            '<button id="freset" type="button">Effacer</button><span id="fcount"></span></div>')


def write_reports(results, outdir, exposures=None, tls_results=None, inventory=None, visual_groups=None,
                  takeovers=None):
    results.sort(key=lambda r: (r["host"], r["port"]))
    with open(outdir / "results.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["host", "port", "ua", "url", "status", "title", "final_url",
                                           "size", "file", "error", "tags", "tech", "favicon_hash",
                                           "header_issues", "visual_group"])
        w.writeheader()
        for r in results:
            row = {k: r.get(k, "") for k in w.fieldnames}
            row["tags"] = " ".join(r.get("tags") or [])
            row["tech"] = "; ".join(tech_label(t) for t in r.get("tech") or [])
            row["header_issues"] = "; ".join(r.get("header_issues") or [])
            row["visual_group"] = r.get("group") or ""
            w.writerow(row)
    firsts = {id(g[0]) for g in visual_groups or []}
    for r in results:
        # A sensitive page is never hidden as a visual duplicate (near-blank listings look alike)
        r["dup"] = bool(r.get("group")) and id(r) not in firsts and not r.get("tags")

    # One section per host:port, one card per user agent
    groups = {}
    for r in results:
        groups.setdefault((r["host"], r["port"]), []).append(r)
    multi_ua = any(len([r for r in g if not r.get("dir")]) > 1 for g in groups.values())

    # host (name or IP) -> exposures of its IPs
    by_host = {}
    for x in exposures or []:
        for h in [x["ip"]] + x["hosts"]:
            by_host.setdefault(h, []).append(x)

    sections = []
    n_diff = 0
    for (host, port), group in groups.items():
        same_page = [r for r in group if not r.get("dir")]  # --dirs captures are other pages
        diffs = find_differences(same_page) if len(same_page) > 1 else []
        n_diff += bool(diffs)
        cards = []
        for r in group:
            e = {k: html.escape(str(r.get(k, ""))) for k in r}
            if r["file"]:
                img = f'<a href="{e["file"]}"><img src="{e["file"]}" loading="lazy"></a>'
            elif r.get("service") or r.get("banner"):
                img = (f'<div class="err" style="color:#333"><b>{html.escape(r.get("service") or "service")} '
                       f'{html.escape(r.get("service_version") or "")}</b><br>'
                       f'<code>{html.escape(r.get("banner") or "")}</code></div>')
            else:
                img = f'<div class="err">{e["error"]}</div>'
            ua = f'<span class="ua">{e["ua"]}</span> ' if multi_ua else ""
            size = f' <span class="size">{int(r["size"]) // 1024} KB</span>' if r.get("size") else ""
            st = str(r.get("status") or "")
            status_class = f"{st[0]}xx" if st[:1] in "12345" and st else "err"
            techs = "|".join(t["name"] for t in r.get("tech") or [])
            query = " ".join([host, str(port), str(r.get("url", "")), str(r.get("final_url", "")),
                              str(r.get("title", "")), st, " ".join(r.get("tags") or []),
                              " ".join(tech_label(t) for t in r.get("tech") or []), str(r.get("ua", ""))]).lower()
            data = (f' data-status="{status_class}" data-tags="{html.escape(" ".join(r.get("tags") or []))}"'
                    f' data-tech="{html.escape(techs)}" data-q="{html.escape(query)}"')
            cards.append(
                f'<div class="card{" dup" if r.get("dup") else ""}"{data}>{img}<div class="meta">{ua}'
                f'<a href="{e["url"]}">{e["url"]}</a><br>'
                f'<b>{e["status"]}</b> {e["title"]}{size}{card_extras(r)}</div></div>'
            )
        badge = (f'<span class="diff">differs: {html.escape(", ".join(diffs))}</span>' if diffs else "")
        alldup = " alldup" if all(r.get("dup") for r in group) else ""
        sections.append(
            f'<section class="{"has-diff" if diffs else "same"}{alldup}"><h2>{html.escape(host)}:{port} {badge}</h2>'
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
{WEB_CSS}
{FILTER_CSS}
{RECON_CSS}
h1.brand{{display:flex;align-items:center;gap:10px;margin:0 0 4px}}
h1.brand img{{width:36px;height:36px}}
</style></head><body>
<h1 class="brand">{f'<img src="{logo}" alt="">' if logo else ""}NetShot</h1><p>{len(groups)} services, {len(results)} captures - {datetime.now():%Y-%m-%d %H:%M}</p>
{takeover_section(takeovers or [])}
{files_section(results)}
{sensitive_section(results)}
{js_section(results)}
{tech_section(inventory or [], vuln_badges, DEFAULT_CREDS)}
{banners_section(results)}
{wellknown_section(results)}
{exposure_table(exposures or [])}
{tls_section(tls_results or [])}
{headers_section(results)}
{groups_section(visual_groups or [])}
{filter_bar(results, inventory)}
{filter_box}
{''.join(sections)}
<script>
var c=document.getElementById('only');
if(c)c.onchange=function(){{document.body.classList.toggle('only',c.checked)}};
var d=document.getElementById('nodup');
if(d)d.onchange=function(){{document.body.classList.toggle('nodup',d.checked)}};
{FILTER_JS}
</script></body></html>"""
    (outdir / "report.html").write_text(page, encoding="utf-8")


async def main_async(args, hosts, ports, log=print, stop=None, on_progress=None, on_shot=None, on_tls=None):
    """Run the scan. log: message callback, stop: threading.Event to abort,
    on_progress(done, total, found) and on_shot(png_path, url, status, title, ua_name):
    optional callbacks (used by the GUI)."""
    if async_playwright is None:
        raise RuntimeError(PLAYWRIGHT_MISSING)
    excl = getattr(args, "exclusions", None)
    if excl:
        hosts = await asyncio.to_thread(excl.filter, hosts, log)
        if not hosts:
            log("[exclusion] plus aucune cible dans le périmètre")
            return []
    proxy = getattr(args, "proxy", None)
    if proxy:
        log(f"[proxy] pages, favicons et dossiers via {proxy['server']}"
            f"{' ; test des ports via SOCKS5' if proxy['scheme'] == 'socks5' else ' ; test des ports en direct'}. "
            "Analyse TLS, enrichissement et NVD restent en direct.")
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    counter = {"done": 0}
    total = len(hosts) * len(ports)
    sem = asyncio.Semaphore(args.concurrency)
    limiter = RateLimiter(getattr(args, "delay", 0))

    async with async_playwright() as pw:
        pw_proxy = playwright_proxy(proxy)
        launch = {"proxy": pw_proxy} if pw_proxy else {}
        browser = await pw.chromium.launch(headless=True, args=["--ignore-certificate-errors"], **launch)
        # One browser context per user agent
        contexts = []
        for ua_name, ua in getattr(args, "user_agents", None) or [("default", None)]:
            opts = {"ignore_https_errors": True, "viewport": {"width": args.width, "height": args.height}}
            if ua is not None:
                opts["user_agent"] = ua
            if pw_proxy:
                opts["proxy"] = pw_proxy  # also used by context.request (favicons, --dirs)
            contexts.append((ua_name, await browser.new_context(**opts)))
        args.web = None
        if getattr(args, "analyze", True):
            # Blank page used to hash the screenshots (no CSP, no network)
            args.web = {"hasher": await contexts[0][1].new_page(), "favicons": {}}
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
    inventory, groups = None, None
    args.takeovers = []
    if args.web is not None and results:
        groups = group_similar(results)
        if groups:
            log(f"[web] {len(groups)} groupe(s) de pages similaires, "
                f"{sum(len(g) - 1 for g in groups)} doublon(s) visuel(s)")
        n_tags = sum(bool(r.get("tags")) for r in results)
        if n_tags:
            log(f"[web] {n_tags} page(s) sensible(s) : voir « Pages sensibles » dans le rapport")
        names = [h for h in hosts if not _is_ip(h)]
        takeovers = []
        if names and not (stop and stop.is_set()):
            pages = {}
            for r in results:
                if r.get("page_text") and r["host"].lower() not in pages:
                    pages[r["host"].lower()] = r["page_text"]
            takeovers = await asyncio.to_thread(check_takeover, names, pages, log)
        args.takeovers = takeovers
        inventory = tech_inventory(results)
        if getattr(args, "enrich", False) and not (stop and stop.is_set()):
            await asyncio.to_thread(lookup_tech_cves, inventory, getattr(args, "keys", None) or {}, log, stop)
        write_tech_csv(inventory, args.output / "technologies.csv")
    takeovers = getattr(args, "takeovers", None) or []
    write_reports(results, args.output, exposures, tls_results, inventory, groups, takeovers)
    write_json(args.output / "results.json", results, exposures, tls_results, inventory, groups, takeovers)
    try:
        write_xlsx(args.output / "results.xlsx", build_sheets(results, exposures, inventory, takeovers))
    except OSError as exc:
        log(f"[export] results.xlsx : {exc}")
    ok = sum(1 for r in results if r["file"])
    log(f"\nDone: {ok} screenshots, {len(results) - ok} errors. Report: {args.output / 'report.html'}")
    return results


def main():
    ap = argparse.ArgumentParser(description="Screenshot web services on IPs / subnets.")
    ap.add_argument("targets", nargs="*", help="IP, CIDR (10.0.0.0/24), AS number (AS3215) or hostname")
    ap.add_argument("-f", "--file", action="append", default=[],
                    help="file with one target per line, or a CSV export (AD, ADCS, CMDB) (repeatable)")
    ap.add_argument("-p", "--ports", default=",".join(map(str, DEFAULT_PORTS)),
                    help="ports, e.g. 80,443,8000-8010, or presets: web (~100 web ports), services "
                         "(SSH, FTP, SMTP, RDP, databases...), default; mixable: web,services,8443 "
                         "(default: %(default)s)")
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
                    help="do not enrich the IPs found (Shodan InternetDB, LeakIX, CISA KEV, EPSS) "
                         "nor look up the CVEs of the versions found (NVD)")
    ap.add_argument("--no-analyze", action="store_true",
                    help="do not analyse the pages (technologies, sensitive pages, security headers, "
                         "favicon hash, similar pages)")
    ap.add_argument("--dns", metavar="DOMAIN",
                    help="show the DNS records of a domain (like dig: ANY, then type by type) and exit")
    ap.add_argument("--dns-server", default="",
                    help="DNS server for --dns, e.g. 1.1.1.1 or 10.0.0.1:53 (default: system resolvers)")
    ap.add_argument("--whois", action="append", default=[], metavar="DOMAIN|IP|ASN",
                    help="who owns a domain, an IP or an AS (RDAP + WHOIS port 43), then exit (repeatable)")
    ap.add_argument("--wordlist", metavar="FILE",
                    help="word list for the 'wordlist' source (DNS brute force), one label per line "
                         "(default: built-in 1,000 words)")
    ap.add_argument("--exclude", action="append", default=[], metavar="TARGETS",
                    help="out-of-scope targets never scanned: IP, CIDR, host name or *.domain, comma "
                         "separated (repeatable); a name that resolves into an excluded range is excluded")
    ap.add_argument("--exclude-file", action="append", default=[], metavar="FILE",
                    help="file of out-of-scope targets, one per line (repeatable)")
    ap.add_argument("--proxy", metavar="URL",
                    help="proxy for the pages: http://127.0.0.1:8080 (Burp) or socks5://host:1080, "
                         "optional user:password@ (http only)")
    ap.add_argument("--files", action="store_true",
                    help="test the sensitive files of assets/files.txt (.env, .git/HEAD, backups, phpinfo, "
                         "actuator...) on every web service; each answer is checked against a signature")
    ap.add_argument("--files-wordlist", metavar="FILE",
                    help="file list for --files: path<TAB>severity<TAB>regex per line (implies --files)")
    ap.add_argument("--dirs", action="store_true",
                    help="test the common folders of assets/dirs.txt (or --dirs-wordlist) on every web "
                         "service and capture the directory listings found ('Index of'); extra requests")
    ap.add_argument("--dirs-wordlist", metavar="FILE",
                    help="folder list for --dirs, one path per line (implies --dirs)")
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
    args.analyze = not args.no_analyze
    try:
        args.proxy = parse_proxy(args.proxy)
        args.exclusions = read_exclusions(args.exclude, args.exclude_file)
    except (ValueError, OSError) as exc:
        ap.error(str(exc))
    if args.files or args.files_wordlist:
        custom = None
        if args.files_wordlist:
            custom = Path(args.files_wordlist).read_text(encoding="utf-8-sig", errors="replace").splitlines()
        args.files = file_rules(custom)
        print(f"--files: {len(args.files)} files per web service", file=sys.stderr)
    else:
        args.files = None
    if args.dirs or args.dirs_wordlist:
        custom = None
        if args.dirs_wordlist:
            custom = Path(args.dirs_wordlist).read_text(encoding="utf-8-sig", errors="replace").splitlines()
        args.dirs = dir_words(custom)
        print(f"--dirs: {len(args.dirs)} folders per web service", file=sys.stderr)
    else:
        args.dirs = None
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
