"""
core/pagecheck.py - Checks inspired by web-check (web-check.xyz), done on the page already loaded.

- mixed content: resources or forms in http:// on an https page
- SRI: third-party scripts and style sheets loaded without an integrity attribute
- trackers and third parties: analytics, advertising, social pixels, consent banners, fonts...
- WAF / protective CDN, read in the headers and cookies (passive), and with --waf-probe one request
  carrying a harmless test string to see whether a filter blocks it (active)

The only extra requests are those of --waf-probe. Same behaviour as pagecheck.go (netshot-go).
"""

import html
import ipaddress
import json
import urllib.parse

from .webinfo import _urls, detect_tech

# Lists, from the live DOM, the resources and forms of the page (absolute URLs, with their integrity
# attribute) and the URLs actually loaded (Resource Timing).
PAGE_RESOURCES_JS = """() => {
  const out = {el: [], res: []};
  const add = (t, u, i, r) => { if (u && out.el.length < 800) out.el.push({t: t, u: String(u), i: i || '', r: r || ''}); };
  document.querySelectorAll('script[src]').forEach(e => add('script', e.src, e.integrity));
  document.querySelectorAll('link[href]').forEach(e => {
    const r = (e.rel || '').toLowerCase();
    if (/stylesheet|preload|modulepreload|icon/.test(r)) add('link', e.href, e.integrity, r);
  });
  document.querySelectorAll('img[src],iframe[src],audio[src],video[src],source[src],embed[src],track[src]')
    .forEach(e => add(e.tagName.toLowerCase(), e.src));
  document.querySelectorAll('object[data]').forEach(e => add('object', e.data));
  document.querySelectorAll('form[action]').forEach(e => add('form', e.action));
  try { performance.getEntriesByType('resource').slice(0, 800).forEach(p => out.res.push(p.name)); } catch (e) {}
  return JSON.stringify(out);
}"""


def _host(url):
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def same_site(a, b):
    """Same host, or same parent domain (last two labels) for host names (as sameSite in Go)."""
    ha, hb = _host(a), _host(b)
    if not ha or not hb:
        return False
    if ha == hb:
        return True
    if _is_ip(hb):
        return False
    root = ".".join(hb.split(".")[-2:])
    return ha == root or ha.endswith("." + root)


def analyze_resources(final_url, raw):
    """JSON of PAGE_RESOURCES_JS -> {"mixed_content", "no_sri", "trackers", "third_party_hosts"}."""
    out = {"mixed_content": [], "no_sri": [], "trackers": [], "third_party_hosts": []}
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return out
    elements = data.get("el") or []
    https = (final_url or "").lower().startswith("https://")
    for el in elements:
        url, tag = str(el.get("u", "")), el.get("t", "")
        low = url.lower()
        if https and low.startswith("http://") and len(out["mixed_content"]) < 50:
            item = ("formulaire" if tag == "form" else tag) + " " + url
            if url not in [m.split(" ", 1)[1] for m in out["mixed_content"]]:
                out["mixed_content"].append(item)
        rel = el.get("r", "")
        is_code = tag == "script" or (tag == "link" and ("stylesheet" in rel or "modulepreload" in rel))
        if (is_code and low.startswith("http") and not el.get("i") and not same_site(url, final_url)
                and url not in out["no_sri"] and len(out["no_sri"]) < 50):
            out["no_sri"].append(url)
    thirds, trackers = set(), set()

    def check(u):
        low = u.lower()
        if not (low.startswith("http://") or low.startswith("https://")):
            return
        h = _host(u)
        if not h or same_site(u, final_url):
            return
        thirds.add(h)
        t = tracker_for(h)
        if t:
            trackers.add(t)

    for el in elements:
        if el.get("t") != "form":
            check(str(el.get("u", "")))
    for u in data.get("res") or []:
        check(str(u))
    out["third_party_hosts"] = sorted(thirds)[:100]
    out["trackers"] = sorted(trackers)
    return out


def page_issues(pc):
    """Sums the checks up in the same list as the header findings."""
    out = []
    mixed = pc.get("mixed_content") or []
    if mixed:
        forms = sum(m.startswith("formulaire ") for m in mixed)
        s = f"contenu mixte : {len(mixed)} ressource(s) en HTTP sur une page HTTPS"
        if forms:
            s += f" (dont {forms} formulaire(s))"
        out.append(s)
    if pc.get("no_sri"):
        out.append(f"SRI absent : {len(pc['no_sri'])} script(s) / feuille(s) de style tiers sans attribut integrity")
    return out


# --- Trackers -----------------------------------------------------------------------------------

# domain (and its subdomains) -> (name, category)
TRACKER_DOMAINS = {
    "google-analytics.com": ("Google Analytics", "mesure d'audience"),
    "analytics.google.com": ("Google Analytics", "mesure d'audience"),
    "googletagmanager.com": ("Google Tag Manager", "gestionnaire de balises"),
    "doubleclick.net": ("Google Ads (DoubleClick)", "publicité"),
    "googlesyndication.com": ("Google AdSense", "publicité"),
    "googleadservices.com": ("Google Ads", "publicité"),
    "adservice.google.com": ("Google Ads", "publicité"),
    "fonts.googleapis.com": ("Google Fonts", "polices (IP transmise à Google)"),
    "fonts.gstatic.com": ("Google Fonts", "polices (IP transmise à Google)"),
    "recaptcha.net": ("Google reCAPTCHA", "anti-robot"),
    "youtube.com": ("YouTube", "vidéo intégrée"),
    "youtube-nocookie.com": ("YouTube (sans cookie)", "vidéo intégrée"),
    "ytimg.com": ("YouTube", "vidéo intégrée"),
    "connect.facebook.net": ("Meta Pixel", "réseau social / publicité"),
    "facebook.com": ("Facebook", "réseau social"),
    "snap.licdn.com": ("LinkedIn Insight", "réseau social / publicité"),
    "ads.linkedin.com": ("LinkedIn Ads", "publicité"),
    "platform.linkedin.com": ("LinkedIn", "réseau social"),
    "static.ads-twitter.com": ("X (Twitter) Ads", "publicité"),
    "analytics.twitter.com": ("X (Twitter) Analytics", "réseau social / publicité"),
    "platform.twitter.com": ("X (Twitter)", "réseau social"),
    "analytics.tiktok.com": ("TikTok Pixel", "réseau social / publicité"),
    "sc-static.net": ("Snapchat Pixel", "réseau social / publicité"),
    "ct.pinterest.com": ("Pinterest Tag", "réseau social / publicité"),
    "bat.bing.com": ("Microsoft Advertising (UET)", "publicité"),
    "clarity.ms": ("Microsoft Clarity", "analyse comportementale"),
    "hotjar.com": ("Hotjar", "analyse comportementale"),
    "hotjar.io": ("Hotjar", "analyse comportementale"),
    "contentsquare.net": ("Contentsquare", "analyse comportementale"),
    "fullstory.com": ("FullStory", "analyse comportementale"),
    "mouseflow.com": ("Mouseflow", "analyse comportementale"),
    "crazyegg.com": ("Crazy Egg", "analyse comportementale"),
    "matomo.cloud": ("Matomo Cloud", "mesure d'audience"),
    "piwik.pro": ("Piwik PRO", "mesure d'audience"),
    "xiti.com": ("AT Internet / Piano", "mesure d'audience"),
    "ati-host.net": ("AT Internet / Piano", "mesure d'audience"),
    "eulerian.net": ("Eulerian", "mesure d'audience"),
    "mixpanel.com": ("Mixpanel", "mesure d'audience"),
    "segment.com": ("Segment", "mesure d'audience"),
    "segment.io": ("Segment", "mesure d'audience"),
    "amplitude.com": ("Amplitude", "mesure d'audience"),
    "heapanalytics.com": ("Heap", "mesure d'audience"),
    "plausible.io": ("Plausible", "mesure d'audience"),
    "mc.yandex.ru": ("Yandex Metrica", "mesure d'audience"),
    "hm.baidu.com": ("Baidu Tongji", "mesure d'audience"),
    "scorecardresearch.com": ("Comscore", "mesure d'audience"),
    "quantserve.com": ("Quantcast", "publicité"),
    "criteo.com": ("Criteo", "publicité"),
    "criteo.net": ("Criteo", "publicité"),
    "taboola.com": ("Taboola", "publicité"),
    "outbrain.com": ("Outbrain", "publicité"),
    "adnxs.com": ("Xandr (AppNexus)", "publicité"),
    "omtrdc.net": ("Adobe Analytics", "mesure d'audience"),
    "demdex.net": ("Adobe Audience Manager", "publicité"),
    "2o7.net": ("Adobe Analytics", "mesure d'audience"),
    "hs-scripts.com": ("HubSpot", "marketing"),
    "hs-analytics.net": ("HubSpot", "marketing"),
    "hsforms.net": ("HubSpot", "marketing"),
    "marketo.net": ("Marketo", "marketing"),
    "pardot.com": ("Salesforce Pardot", "marketing"),
    "js-agent.newrelic.com": ("New Relic", "monitoring"),
    "nr-data.net": ("New Relic", "monitoring"),
    "browser.sentry-cdn.com": ("Sentry", "monitoring"),
    "sentry.io": ("Sentry", "monitoring"),
    "browser-intake-datadoghq.com": ("Datadog RUM", "monitoring"),
    "browser-intake-datadoghq.eu": ("Datadog RUM", "monitoring"),
    "cookielaw.org": ("OneTrust", "consentement"),
    "onetrust.com": ("OneTrust", "consentement"),
    "didomi.io": ("Didomi", "consentement"),
    "axeptio.eu": ("Axeptio", "consentement"),
    "cookiebot.com": ("Cookiebot", "consentement"),
    "consentmanager.net": ("consentmanager", "consentement"),
    "trustcommander.net": ("Commanders Act", "consentement"),
    "tagcommander.com": ("Commanders Act", "gestionnaire de balises"),
    "widget.intercom.io": ("Intercom", "chat"),
    "intercomcdn.com": ("Intercom", "chat"),
    "zdassets.com": ("Zendesk", "chat"),
    "client.crisp.chat": ("Crisp", "chat"),
    "tawk.to": ("Tawk.to", "chat"),
}


def tracker_for(host):
    """'name (category)' when host is a known tracker or third party, else ''."""
    h = (host or "").lower().rstrip(".")
    while h:
        if h in TRACKER_DOMAINS:
            name, cat = TRACKER_DOMAINS[h]
            return f"{name} ({cat})"
        _, sep, rest = h.partition(".")
        if not sep or "." not in rest:
            break
        h = rest
    return ""


# --- WAF / protective CDN -------------------------------------------------------------------------
# Same pattern places as the technologies: header:<name>, cookie, html.

WAF_RULES = [
    ("Cloudflare", [], False, [("header:cf-ray", r"."), ("header:server", r"^cloudflare"),
                               ("cookie", r"^(__cf_bm|__cflb|cf_clearance)$")]),
    ("Akamai", [], False, [("header:server", r"AkamaiGHost|AkamaiNetStorage"), ("header:x-akamai-transformed", r"."),
                           ("cookie", r"^(ak_bmsc|bm_sz|_abck)$")]),
    ("Imperva / Incapsula", [], False, [("header:x-iinfo", r"."), ("header:x-cdn", r"Incapsula|Imperva"),
                                        ("cookie", r"^(incap_ses_|visid_incap_|nlbi_)")]),
    ("Sucuri", [], False, [("header:x-sucuri-id", r"."), ("header:x-sucuri-cache", r"."), ("header:server", r"Sucuri")]),
    ("F5 BIG-IP ASM", [], False, [("cookie", r"^TS[0-9a-f]{6,}$"), ("header:x-wa-info", r".")]),
    ("AWS WAF", [], False, [("cookie", r"^aws-waf-token$"), ("header:x-amzn-waf-action", r".")]),
    ("AWS CloudFront", [], False, [("header:x-amz-cf-id", r"."), ("header:via", r"CloudFront")]),
    ("Azure Front Door", [], False, [("header:x-azure-ref", r".")]),
    ("Azure Application Gateway", [], False, [("header:server", r"Microsoft-Azure-Application-Gateway")]),
    ("Fortinet FortiWeb", [], False, [("cookie", r"^FORTIWAFSID$"), ("header:server", r"FortiWeb")]),
    ("Barracuda", [], False, [("cookie", r"^(barra_counter_session|BNI__BARRACUDA_LB_COOKIE)$"),
                              ("header:server", r"Barracuda")]),
    ("Citrix NetScaler AppFirewall", [], False, [("cookie", r"^(ns_af|citrix_ns_id)"), ("header:via", r"NS-CACHE"),
                                                 ("header:cneonction", r"."), ("header:nncoection", r".")]),
    ("ModSecurity", [], False, [("header:server", r"Mod_Security|NOYB")]),
    ("Fastly", [], False, [("header:x-fastly-request-id", r"."), ("header:x-served-by", r"^cache-")]),
    ("DDoS-Guard", [], False, [("header:server", r"ddos-guard"), ("cookie", r"^__ddg")]),
    ("Wallarm", [], False, [("header:server", r"nginx-wallarm")]),
    ("Reblaze", [], False, [("cookie", r"^rbzid$"), ("header:server", r"Reblaze")]),
    ("Radware", [], False, [("header:x-sl-compstate", r".")]),
]

# Block page returned to the --waf-probe request.
WAF_BLOCK_RULES = [
    ("Cloudflare", [], False, [("html", r"Attention Required! \| Cloudflare|cf-error-details|Cloudflare Ray ID")]),
    ("Imperva / Incapsula", [], False, [("html", r"Incapsula incident ID|_Incapsula_Resource")]),
    ("Akamai", [], False, [("html", r"Access Denied.{0,200}Reference #")]),
    ("AWS WAF", [], False, [("html", r"Request blocked\..{0,400}(CloudFront|AWS)")]),
    ("F5 BIG-IP ASM", [], False, [("html", r"The requested URL was rejected\. Please consult with your administrator")]),
    ("ModSecurity", [], False, [("html", r"Mod_Security|This error was generated by Mod_Security|ModSecurity Action")]),
    ("Sucuri", [], False, [("html", r"Sucuri WebSite Firewall|sucuri\.net/privacy-policy")]),
    ("Fortinet FortiWeb", [], False, [("html", r"FortiWeb|\.fgd_icon|Web Page Blocked")]),
    ("Barracuda", [], False, [("html", r"Barracuda Networks|barra_counter_session")]),
    ("Citrix NetScaler AppFirewall", [], False, [("html", r"NS Transaction ID|AppFW Session ID")]),
    ("Wordfence", [], False, [("html", r"Generated by Wordfence|wordfence\.com")]),
    ("NAXSI", [], False, [("html", r"naxsi")]),
    ("Wallarm", [], False, [("html", r"nginx-wallarm")]),
    ("DDoS-Guard", [], False, [("html", r"DDoS-Guard")]),
]


def match_rules(rules, headers, page_html=""):
    """Names of the rules that match (no version)."""
    out = []
    for t in detect_tech(headers, page_html, "", rules=rules):
        if t["name"] not in out:
            out.append(t["name"])
    return out


def detect_waf(headers):
    """Protections visible in the headers and cookies of a page."""
    return match_rules(WAF_RULES, headers)


# Harmless (nothing is executed nor read) but looks like XSS, SQL injection and path traversal,
# which any WAF blocks.
WAF_PROBE_VALUE = "<script>alert(1)</script>' OR '1'='1 ../../../../etc/passwd"
BLOCK_CODES = {400, 403, 406, 418, 429, 501, 503, 999}


async def probe_waf(context, base_url, timeout_s):
    """--waf-probe: compare a normal request with one carrying WAF_PROBE_VALUE in the query string.
    Returns a one-line verdict, or '' when the service does not answer."""
    async def get(url):
        resp = await context.request.get(url, timeout=timeout_s * 1000, max_redirects=2)
        body = (await resp.body())[:65536].decode("latin-1")
        return resp.status, resp.headers_array, body

    try:
        st0, _, body0 = await get(base_url)
    except Exception:
        return ""
    sep = "&" if "?" in base_url else "?"
    try:
        st1, hs1, body1 = await get(f"{base_url}{sep}netshot_waf_test={urllib.parse.quote(WAF_PROBE_VALUE)}")
    except Exception as exc:
        return f"bloqué (connexion coupée : {str(exc).splitlines()[0][:80] if str(exc) else type(exc).__name__})"
    sig0 = match_rules(WAF_BLOCK_RULES, [], body0)
    sig1 = match_rules(WAF_BLOCK_RULES, [], body1)
    names = [n for n in sig1 if n not in sig0]  # a signature already on the normal page proves nothing
    names += [n for n in detect_waf(hs1) if n not in names]
    blocked = (st1 != st0 and st1 in BLOCK_CODES) or len(sig1) > len(sig0)
    who = f" : {', '.join(names)}" if names else ""
    if blocked:
        return f"bloqué ({st1} au lieu de {st0}){who}"
    return f"non bloqué ({st1}, comme la page normale)"


# --- Report -----------------------------------------------------------------------------------------

def page_checks_section(results):
    """Mixed content, SRI, trackers and WAF, one row per service."""
    e = html.escape
    waf_rows, mix_rows, track_rows = [], [], []
    track_count = {}
    seen = set()
    n_waf = n_mixed = n_sri = 0

    def lines(items):
        shown = [e(x) for x in items[:10]]
        if len(items) > 10:
            shown.append(f"+{len(items) - 10}")
        return "<br>".join(shown)

    for r in results:
        if not r.get("file") or r["url"] in seen:
            continue
        seen.add(r["url"])
        waf, probe = r.get("waf") or [], r.get("waf_probe") or ""
        if waf or probe:
            n_waf += bool(waf or probe.startswith("bloqué"))
            waf_rows.append(f"<tr><td>{_urls([r['url']])}</td><td>{e(', '.join(waf))}</td><td>{e(probe)}</td></tr>")
        mixed, nosri = r.get("mixed_content") or [], r.get("no_sri") or []
        if mixed or nosri:
            n_mixed += bool(mixed)
            n_sri += bool(nosri)
            mix_rows.append(f"<tr><td>{_urls([r['url']])}</td><td>{lines(mixed)}</td><td>{lines(nosri)}</td></tr>")
        trackers, thirds = r.get("trackers") or [], r.get("third_party_hosts") or []
        if trackers or thirds:
            for t in trackers:
                track_count[t] = track_count.get(t, 0) + 1
            track_rows.append(f"<tr><td>{_urls([r['url']])}</td><td>{e(', '.join(trackers))}</td>"
                              f"<td>{len(thirds)}</td></tr>")
    out = ""
    if waf_rows:
        out += (f"<details><summary><b>WAF / CDN de protection</b> - {n_waf} service(s) protégé(s)</summary>"
                f"<table><tr><th>URL</th><th>Vu dans les en-têtes / cookies</th><th>Test actif (--waf-probe)</th></tr>"
                f"{''.join(waf_rows)}</table></details>")
    if mix_rows:
        out += (f"<details><summary><b>Contenu mixte et SRI</b> - {n_mixed} page(s) avec contenu mixte, {n_sri} avec "
                f"des scripts tiers sans SRI</summary><table><tr><th>URL</th><th>Contenu mixte (HTTP sur page HTTPS)"
                f"</th><th>Scripts / styles tiers sans integrity</th></tr>{''.join(mix_rows)}</table></details>")
    if track_rows:
        names = sorted(track_count, key=lambda n: (-track_count[n], n))
        summary = ", ".join(f"{n} : {track_count[n]}" for n in names)
        summary = f" : {e(summary[:300])}" if summary else ""
        out += (f"<details><summary><b>Traqueurs et tiers</b> - {len(names)} traqueur(s) connu(s){summary}</summary>"
                f"<table><tr><th>URL</th><th>Traqueurs / services tiers connus</th><th>Hôtes tiers</th></tr>"
                f"{''.join(track_rows)}</table></details>")
    return out
