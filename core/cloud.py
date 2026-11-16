"""
core/cloud.py - cloud and SaaS footprint of the scanned organisation (passive, no key). Same
behaviour as cloud.go (netshot-go):

1. Microsoft 365 / Entra ID tenant: OpenID configuration (tenant ID, region), getuserrealm (managed
   or federated, identity provider), Autodiscover (other domains of the tenant). Google Workspace
   from the MX records.
2. SaaS, PaaS and IaaS recognised from the TXT (verification tokens), SPF includes, MX, NS and the
   CNAME of the scanned names and of a few standard names (autodiscover, enterpriseregistration…).
3. Public IPs mapped to AWS, Azure, Google Cloud and Cloudflare (service, region) with the ranges
   those providers publish (cached 7 days).
4. Dangling CNAMEs: the subdomain takeover check (recon.py) runs with this footprint too.
5. Report section, cloud.csv, "Cloud et SaaS" sheet, "cloud" in results.json.

Domains of the tenant and the federation host of the organisation are added to the scan (all
ports); its SaaS tenant pages (SharePoint, Okta…) are added on 443 only. --no-cloud-targets keeps
the footprint without adding anything.
"""

import csv
import html
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .sources import is_internal_ip, registrable_domain

# (source, lowercase substring - TXT: prefix of the record, service, category)
CLOUD_SIGS = [
    # TXT verification tokens
    ("TXT", "ms=", "Microsoft 365", "Messagerie / collaboration"),
    ("TXT", "google-site-verification=", "Google (Search Console / Workspace)", "Vérification"),
    ("TXT", "atlassian-domain-verification=", "Atlassian Cloud", "Développement / tickets"),
    ("TXT", "docusign=", "DocuSign", "Signature électronique"),
    ("TXT", "facebook-domain-verification=", "Meta (Facebook)", "Marketing"),
    ("TXT", "workplace-domain-verification=", "Meta Workplace", "Collaboration"),
    ("TXT", "adobe-idp-site-verification=", "Adobe (SSO)", "Bureautique"),
    ("TXT", "adobe-sign-verification=", "Adobe Acrobat Sign", "Signature électronique"),
    ("TXT", "apple-domain-verification=", "Apple Business", "Gestion des appareils"),
    ("TXT", "zoom_verify_", "Zoom", "Visioconférence"),
    ("TXT", "slack-domain-verification=", "Slack", "Collaboration"),
    ("TXT", "dropbox-domain-verification=", "Dropbox", "Stockage"),
    ("TXT", "box-domain-verification=", "Box", "Stockage"),
    ("TXT", "stripe-verification=", "Stripe", "Paiement"),
    ("TXT", "hubspot-developer-verification=", "HubSpot", "CRM / marketing"),
    ("TXT", "hubspot-site-verification=", "HubSpot", "CRM / marketing"),
    ("TXT", "pardot", "Salesforce Pardot", "CRM / marketing"),
    ("TXT", "cisco-ci-domain-verification=", "Cisco Webex", "Visioconférence"),
    ("TXT", "webexdomainverification", "Cisco Webex", "Visioconférence"),
    ("TXT", "teamviewer-sso-verification=", "TeamViewer", "Accès distant"),
    ("TXT", "logmein-verification-code=", "GoTo (LogMeIn)", "Accès distant"),
    ("TXT", "citrix-verification-code=", "Citrix Cloud", "Accès distant"),
    ("TXT", "miro-verification=", "Miro", "Collaboration"),
    ("TXT", "onetrust-domain-verification=", "OneTrust", "Conformité"),
    ("TXT", "knowbe4-site-verification=", "KnowBe4", "Sensibilisation"),
    ("TXT", "globalsign-domain-verification=", "GlobalSign", "Certificats"),
    ("TXT", "mongodb-site-verification=", "MongoDB Atlas", "Base de données"),
    ("TXT", "status-page-domain-verification=", "Atlassian Statuspage", "Supervision"),
    ("TXT", "brevo-code:", "Brevo", "E-mailing"),
    ("TXT", "sendinblue-code:", "Brevo (Sendinblue)", "E-mailing"),
    ("TXT", "zoho-verification=", "Zoho", "Bureautique"),
    ("TXT", "lastpass-verification-code=", "LastPass", "Mots de passe"),
    ("TXT", "openai-domain-verification=", "OpenAI", "IA"),
    ("TXT", "anthropic-domain-verification", "Anthropic", "IA"),
    ("TXT", "canva-site-verification=", "Canva", "Bureautique"),
    ("TXT", "heroku-domain-verification=", "Heroku", "PaaS"),
    ("TXT", "jamf-site-verification=", "Jamf", "Gestion des appareils"),
    ("TXT", "airtable-verification=", "Airtable", "Bureautique"),
    ("TXT", "smartsheet-site-validation=", "Smartsheet", "Bureautique"),
    ("TXT", "yandex-verification:", "Yandex", "Vérification"),
    ("TXT", "amazonses:", "AWS SES", "E-mailing"),
    # SPF includes
    ("SPF", "spf.protection.outlook.com", "Microsoft 365 (Exchange Online)", "Messagerie / collaboration"),
    ("SPF", "_spf.google.com", "Google Workspace", "Messagerie / collaboration"),
    ("SPF", "_spf.salesforce.com", "Salesforce", "CRM / marketing"),
    ("SPF", "sendgrid.net", "SendGrid", "E-mailing"),
    ("SPF", "servers.mcsv.net", "Mailchimp", "E-mailing"),
    ("SPF", "mail.zendesk.com", "Zendesk", "Support"),
    ("SPF", "hubspotemail.net", "HubSpot", "CRM / marketing"),
    ("SPF", "amazonses.com", "AWS SES", "E-mailing"),
    ("SPF", "mailgun.org", "Mailgun", "E-mailing"),
    ("SPF", "spf.mandrillapp.com", "Mailchimp Transactional", "E-mailing"),
    ("SPF", "sendinblue.com", "Brevo", "E-mailing"),
    ("SPF", "spf.brevo.com", "Brevo", "E-mailing"),
    ("SPF", "mailjet.com", "Mailjet", "E-mailing"),
    ("SPF", "mtasv.net", "Postmark", "E-mailing"),
    ("SPF", "sparkpostmail.com", "SparkPost", "E-mailing"),
    ("SPF", "mlsend.com", "MailerLite", "E-mailing"),
    ("SPF", "elasticemail.com", "Elastic Email", "E-mailing"),
    ("SPF", "smtp2go.com", "SMTP2GO", "E-mailing"),
    ("SPF", "freshdesk.com", "Freshdesk", "Support"),
    ("SPF", "atlassian.net", "Atlassian Cloud", "Développement / tickets"),
    ("SPF", "mktomail.com", "Marketo", "CRM / marketing"),
    ("SPF", "service-now.com", "ServiceNow", "Support"),
    ("SPF", "pphosted.com", "Proofpoint", "Sécurité e-mail"),
    ("SPF", "mimecast", "Mimecast", "Sécurité e-mail"),
    ("SPF", "messagelabs.com", "Broadcom Email Security", "Sécurité e-mail"),
    ("SPF", "zoho.", "Zoho Mail", "Messagerie / collaboration"),
    ("SPF", "mx.ovh.com", "OVHcloud (e-mail)", "Messagerie / collaboration"),
    ("SPF", "ionos.", "IONOS", "Messagerie / collaboration"),
    ("SPF", "_spf.docusign.", "DocuSign", "Signature électronique"),
    # MX
    ("MX", "mail.protection.outlook.com", "Microsoft 365 (Exchange Online)", "Messagerie / collaboration"),
    ("MX", "google.com", "Google Workspace", "Messagerie / collaboration"),
    ("MX", "googlemail.com", "Google Workspace", "Messagerie / collaboration"),
    ("MX", "pphosted.com", "Proofpoint", "Sécurité e-mail"),
    ("MX", "mimecast.com", "Mimecast", "Sécurité e-mail"),
    ("MX", "messagelabs.com", "Broadcom Email Security", "Sécurité e-mail"),
    ("MX", "barracudanetworks.com", "Barracuda Email Protection", "Sécurité e-mail"),
    ("MX", "iphmx.com", "Cisco Secure Email", "Sécurité e-mail"),
    ("MX", "trendmicro", "Trend Micro Email Security", "Sécurité e-mail"),
    ("MX", "sophos.com", "Sophos Email", "Sécurité e-mail"),
    ("MX", "vadesecure.com", "Vade (Hornetsecurity)", "Sécurité e-mail"),
    ("MX", "hornetsecurity.com", "Hornetsecurity", "Sécurité e-mail"),
    ("MX", "mailinblack.com", "Mailinblack", "Sécurité e-mail"),
    ("MX", "altospam.com", "Altospam", "Sécurité e-mail"),
    ("MX", "mail.ovh.net", "OVHcloud (e-mail)", "Messagerie / collaboration"),
    ("MX", "zoho.", "Zoho Mail", "Messagerie / collaboration"),
    ("MX", "secureserver.net", "GoDaddy (e-mail)", "Messagerie / collaboration"),
    ("MX", "ionos.", "IONOS (e-mail)", "Messagerie / collaboration"),
    ("MX", "gandi.net", "Gandi (e-mail)", "Messagerie / collaboration"),
    # NS
    ("NS", ".awsdns-", "AWS Route 53", "DNS"),
    ("NS", "azure-dns.", "Azure DNS", "DNS"),
    ("NS", ".ns.cloudflare.com", "Cloudflare DNS", "DNS"),
    ("NS", "googledomains.com", "Google Cloud DNS", "DNS"),
    ("NS", "ns-cloud-", "Google Cloud DNS", "DNS"),
    ("NS", ".ovh.net", "OVHcloud DNS", "DNS"),
    ("NS", "gandi.net", "Gandi DNS", "DNS"),
    ("NS", "ui-dns.", "IONOS DNS", "DNS"),
    # CNAME targets
    ("CNAME", ".azurewebsites.net", "Azure App Service", "PaaS"),
    ("CNAME", ".azurestaticapps.net", "Azure Static Web Apps", "PaaS"),
    ("CNAME", ".cloudapp.azure.com", "Azure (machine virtuelle)", "IaaS"),
    ("CNAME", ".cloudapp.net", "Azure Cloud Service", "IaaS"),
    ("CNAME", ".blob.core.windows.net", "Azure Blob Storage", "Stockage"),
    ("CNAME", ".web.core.windows.net", "Azure Storage (site statique)", "Stockage"),
    ("CNAME", ".azurefd.net", "Azure Front Door", "CDN"),
    ("CNAME", ".azureedge.net", "Azure CDN", "CDN"),
    ("CNAME", ".trafficmanager.net", "Azure Traffic Manager", "PaaS"),
    ("CNAME", ".azure-api.net", "Azure API Management", "PaaS"),
    ("CNAME", ".sharepoint.com", "SharePoint Online", "Messagerie / collaboration"),
    ("CNAME", "autodiscover.outlook.com", "Microsoft 365 (Exchange Online)", "Messagerie / collaboration"),
    ("CNAME", "webdir.online.lync.com", "Microsoft Teams / Skype Entreprise", "Visioconférence"),
    ("CNAME", "sipdir.online.lync.com", "Microsoft Teams / Skype Entreprise", "Visioconférence"),
    ("CNAME", "enterpriseregistration.windows.net", "Entra ID (inscription des appareils)", "Identité"),
    ("CNAME", "manage.microsoft.com", "Microsoft Intune", "Gestion des appareils"),
    ("CNAME", ".s3.amazonaws.com", "AWS S3", "Stockage"),
    ("CNAME", ".s3-website", "AWS S3 (site statique)", "Stockage"),
    ("CNAME", ".elb.amazonaws.com", "AWS Elastic Load Balancing", "IaaS"),
    ("CNAME", ".compute.amazonaws.com", "AWS EC2", "IaaS"),
    ("CNAME", ".execute-api.", "AWS API Gateway", "PaaS"),
    ("CNAME", ".elasticbeanstalk.com", "AWS Elastic Beanstalk", "PaaS"),
    ("CNAME", ".cloudfront.net", "AWS CloudFront", "CDN"),
    ("CNAME", ".awsglobalaccelerator.com", "AWS Global Accelerator", "CDN"),
    ("CNAME", ".amplifyapp.com", "AWS Amplify", "PaaS"),
    ("CNAME", ".amazonaws.com", "AWS", "IaaS"),
    ("CNAME", ".appspot.com", "Google App Engine", "PaaS"),
    ("CNAME", ".run.app", "Google Cloud Run", "PaaS"),
    ("CNAME", ".web.app", "Firebase Hosting", "PaaS"),
    ("CNAME", ".firebaseapp.com", "Firebase Hosting", "PaaS"),
    ("CNAME", "storage.googleapis.com", "Google Cloud Storage", "Stockage"),
    ("CNAME", "ghs.googlehosted.com", "Google Sites / App Engine", "PaaS"),
    ("CNAME", ".cdn.cloudflare.net", "Cloudflare", "CDN"),
    ("CNAME", ".pages.dev", "Cloudflare Pages", "PaaS"),
    ("CNAME", ".workers.dev", "Cloudflare Workers", "PaaS"),
    ("CNAME", ".akamaiedge.net", "Akamai", "CDN"),
    ("CNAME", ".edgekey.net", "Akamai", "CDN"),
    ("CNAME", ".edgesuite.net", "Akamai", "CDN"),
    ("CNAME", ".fastly.net", "Fastly", "CDN"),
    ("CNAME", ".fastlylb.net", "Fastly", "CDN"),
    ("CNAME", ".incapdns.net", "Imperva", "CDN"),
    ("CNAME", ".sucuri.net", "Sucuri", "CDN"),
    ("CNAME", ".b-cdn.net", "Bunny CDN", "CDN"),
    ("CNAME", ".herokuapp.com", "Heroku", "PaaS"),
    ("CNAME", ".herokudns.com", "Heroku", "PaaS"),
    ("CNAME", "vercel-dns.com", "Vercel", "PaaS"),
    ("CNAME", ".vercel.app", "Vercel", "PaaS"),
    ("CNAME", ".netlify.app", "Netlify", "PaaS"),
    ("CNAME", ".github.io", "GitHub Pages", "PaaS"),
    ("CNAME", ".gitlab.io", "GitLab Pages", "PaaS"),
    ("CNAME", ".okta.com", "Okta", "Identité"),
    ("CNAME", ".okta-emea.com", "Okta", "Identité"),
    ("CNAME", ".oktapreview.com", "Okta", "Identité"),
    ("CNAME", ".onelogin.com", "OneLogin", "Identité"),
    ("CNAME", ".auth0.com", "Auth0", "Identité"),
    ("CNAME", ".pingone.", "Ping Identity", "Identité"),
    ("CNAME", ".atlassian.net", "Atlassian Cloud", "Développement / tickets"),
    ("CNAME", ".statuspage.io", "Atlassian Statuspage", "Supervision"),
    ("CNAME", ".zendesk.com", "Zendesk", "Support"),
    ("CNAME", ".freshdesk.com", "Freshdesk", "Support"),
    ("CNAME", ".freshservice.com", "Freshservice", "Support"),
    ("CNAME", ".service-now.com", "ServiceNow", "Support"),
    ("CNAME", ".force.com", "Salesforce", "CRM / marketing"),
    ("CNAME", ".salesforce.com", "Salesforce", "CRM / marketing"),
    ("CNAME", ".hubspot.net", "HubSpot", "CRM / marketing"),
    ("CNAME", ".hs-sites.com", "HubSpot", "CRM / marketing"),
    ("CNAME", ".mktoweb.com", "Marketo", "CRM / marketing"),
    ("CNAME", ".pardot.com", "Salesforce Pardot", "CRM / marketing"),
    ("CNAME", ".myshopify.com", "Shopify", "E-commerce"),
    ("CNAME", ".wpengine.com", "WP Engine", "Hébergement web"),
    ("CNAME", ".wordpress.com", "WordPress.com", "Hébergement web"),
    ("CNAME", ".webflow.io", "Webflow", "Hébergement web"),
    ("CNAME", "webflow.com", "Webflow", "Hébergement web"),
    ("CNAME", ".squarespace.com", "Squarespace", "Hébergement web"),
    ("CNAME", ".wixdns.net", "Wix", "Hébergement web"),
    ("CNAME", ".ghost.io", "Ghost", "Hébergement web"),
    ("CNAME", ".kinsta.cloud", "Kinsta", "Hébergement web"),
    ("CNAME", ".pantheonsite.io", "Pantheon", "Hébergement web"),
    ("CNAME", ".readthedocs.io", "Read the Docs", "Documentation"),
    ("CNAME", ".helpscoutdocs.com", "Help Scout", "Support"),
    ("CNAME", "intercom.help", "Intercom", "Support"),
    ("CNAME", ".sendgrid.net", "SendGrid", "E-mailing"),
    ("CNAME", ".docusign.net", "DocuSign", "Signature électronique"),
    ("CNAME", ".zoom.us", "Zoom", "Visioconférence"),
    ("CNAME", ".webex.com", "Cisco Webex", "Visioconférence"),
    ("CNAME", ".ovh.net", "OVHcloud", "Hébergement web"),
    ("CNAME", ".scw.cloud", "Scaleway", "IaaS"),
    ("CNAME", ".oraclecloud.com", "Oracle Cloud", "IaaS"),
    ("CNAME", ".ondigitalocean.app", "DigitalOcean App Platform", "PaaS"),
    ("CNAME", ".digitaloceanspaces.com", "DigitalOcean Spaces", "Stockage"),]

MS_LOGIN = "https://login.microsoftonline.com"
MS_AUTODISCOVER = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
SPF_INCLUDE = re.compile(r"(?i)\b(?:include|redirect|exists)[:=]([^\s\"]+)")
TENANT_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# the link may be JSON-escaped in the page ("https:\/\/download.microsoft.com\/download\/…")
AZURE_TAGS_URL = re.compile(r"https:(?:\\?/){2}download\.microsoft\.com(?:\\?/)download(?:\\?/)[^\"'\s<>]+?"
                            r"ServiceTags_Public_\d+\.json")
INTERNAL_TLDS = {"lan", "local", "localdomain", "internal", "intra", "intranet", "corp", "home", "test",
                 "localhost", "invalid", "example"}
PROBE_NAMES = ["autodiscover", "lyncdiscover", "sip", "enterpriseregistration", "enterpriseenrollment", "www"]
CACHE_DAYS = 7


def match_sig(source, value):
    """-> (service, category) of the first signature of source that value matches, or None."""
    v = (value or "").strip('". ').lower()
    for src, m, service, category in CLOUD_SIGS:
        if src == source and (v.startswith(m) if source == "TXT" else m in v):
            return service, category
    return None


def record_services(domain, recs):
    """Services recognised in the TXT, MX and NS records of domain."""
    out = []
    for r in recs:
        data = r["data"].strip('"')
        if r["type"] == "TXT":
            if data.lower().startswith("v=spf1"):
                for inc in SPF_INCLUDE.findall(data):
                    m = match_sig("SPF", inc)
                    if m:
                        out.append(_svc(m, "SPF", domain, inc))
                continue
            m = match_sig("TXT", data)
            if m:
                out.append(_svc(m, "TXT", domain, data if len(data) <= 70 else data[:70] + "…"))
        elif r["type"] in ("MX", "NS"):
            target = (data.split() or [data])[-1]
            m = match_sig(r["type"], target)
            if m:
                out.append(_svc(m, r["type"], domain, target.rstrip(".")))
    return out


def _svc(m, source, host, evidence):
    return {"service": m[0], "category": m[1], "source": source, "host": host, "evidence": evidence}


# --- Microsoft 365 / Entra ID -------------------------------------------------------------------

def _get_json(url, timeout=15):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0 (Netshot)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read(4 << 20) or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {}


AUTODISCOVER_BODY = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soap:Header><a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
<a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo></soap:Header>
<soap:Body><GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
<Request><Domain>{}</Domain></Request></GetFederationInformationRequestMessage></soap:Body></soap:Envelope>"""


def parse_autodiscover(raw):
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return []
    out = {(el.text or "").strip().lower() for el in root.iter() if el.tag.rsplit("}", 1)[-1] == "Domain"}
    return sorted(d for d in out if d)


def autodiscover_domains(domain):
    """Domains of the tenant that holds domain (Exchange Online GetFederationInformation). Microsoft
    may answer with fewer domains than the tenant has."""
    req = urllib.request.Request(MS_AUTODISCOVER, data=AUTODISCOVER_BODY.format(html.escape(domain)).encode(),
                                 method="POST", headers={
                                     "Content-Type": "text/xml; charset=utf-8", "User-Agent": "AutodiscoverClient",
                                     "SOAPAction": '"http://schemas.microsoft.com/exchange/2010/Autodiscover/'
                                                   'Autodiscover/GetFederationInformation"'})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return parse_autodiscover(resp.read(4 << 20))
    except (urllib.error.URLError, OSError, ValueError):
        return []


def microsoft_tenant(domain):
    """Entra ID tenant of domain, or None."""
    code, oidc = _get_json(f"{MS_LOGIN}/{urllib.parse.quote(domain)}/v2.0/.well-known/openid-configuration")
    try:
        _, realm = _get_json(f"{MS_LOGIN}/getuserrealm.srf?json=1&login=" + urllib.parse.quote("netshot@" + domain))
    except (urllib.error.URLError, OSError, ValueError):
        realm = {}
    ns = realm.get("NameSpaceType", "")
    if code != 200 and ns in ("", "Unknown"):
        return None
    m = TENANT_GUID.search(oidc.get("issuer", "") if code == 200 else "")
    t = {"provider": "Microsoft 365 / Entra ID", "domain": domain, "tenant_id": m.group(0) if m else "",
         "name": "", "region": oidc.get("tenant_region_scope", "") if code == 200 else "", "auth": "", "idp": "",
         "brand": realm.get("FederationBrandName", ""), "domains": []}
    if ns == "Managed":
        t["auth"] = "gérée (Entra ID)"
    elif ns == "Federated":
        t["auth"] = "fédérée"
        t["idp"] = (urllib.parse.urlsplit(realm.get("AuthURL", "")).hostname or "").lower()
    t["domains"] = autodiscover_domains(domain)
    for d in t["domains"]:
        if d.endswith(".onmicrosoft.com") and not d.endswith(".mail.onmicrosoft.com"):
            t["name"] = d[:-len(".onmicrosoft.com")]
    return t


# --- Provider IP ranges -------------------------------------------------------------------------

_ranges = None
_ranges_lock = threading.Lock()


def _cache_dir():
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "netshot" / "cloud-ranges"


def _download(url, limit=64 << 20):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Netshot)"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read(limit)


def _cached(name, url):
    """Body of url, kept CACHE_DAYS in the user cache; a stale copy is used when the download fails."""
    path = _cache_dir() / name
    try:
        if time.time() - path.stat().st_mtime < CACHE_DAYS * 86400:
            return path.read_bytes()
    except OSError:
        pass
    try:
        data = _download(url) if url else None
        if data is None:
            raise OSError("lien des Service Tags introuvable sur la page de téléchargement Microsoft")
    except (urllib.error.URLError, OSError, ValueError):
        if path.exists():
            return path.read_bytes()
        raise
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    except OSError:
        pass
    return data


def _azure_link():
    path = _cache_dir() / "azure.json"
    try:
        if time.time() - path.stat().st_mtime < CACHE_DAYS * 86400:
            return None  # fresh cache: no need for the link
    except OSError:
        pass
    try:
        page = _download("https://www.microsoft.com/en-us/download/details.aspx?id=56519", 4 << 20).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError):
        return ""
    m = AZURE_TAGS_URL.search(page)
    return m.group(0).replace("\\/", "/") if m else ""


def load_ranges(log=print):
    """[(network, provider, service, region)] of AWS, Azure, Google Cloud and Cloudflare."""
    global _ranges
    with _ranges_lock:
        if _ranges is not None:
            return _ranges
        out = []

        def add(prefix, provider, service="", region=""):
            try:
                out.append((ipaddress.ip_network(prefix.strip(), strict=False), provider, service, region))
            except ValueError:
                pass
        try:
            j = json.loads(_cached("aws.json", "https://ip-ranges.amazonaws.com/ip-ranges.json"))
            for p in j.get("prefixes", []) + j.get("ipv6_prefixes", []):
                svc = p.get("service", "")
                add(p.get("ip_prefix") or p.get("ipv6_prefix", ""), "AWS", "" if svc == "AMAZON" else svc,
                    p.get("region", ""))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log(f"[cloud] plages AWS indisponibles : {exc}")
        try:
            j = json.loads(_cached("gcp.json", "https://www.gstatic.com/ipranges/cloud.json"))
            for p in j.get("prefixes", []):
                add(p.get("ipv4Prefix") or p.get("ipv6Prefix", ""), "Google Cloud", "", p.get("scope", ""))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log(f"[cloud] plages Google Cloud indisponibles : {exc}")
        for v in ("ips-v4", "ips-v6"):
            try:
                for line in _cached(f"cloudflare-{v}.txt", f"https://www.cloudflare.com/{v}").decode().splitlines():
                    add(line, "Cloudflare")
            except (urllib.error.URLError, OSError, ValueError):
                pass
        try:
            link = _azure_link()
            j = json.loads(_cached("azure.json", link) if link is not None else (_cache_dir() / "azure.json").read_bytes())
            for v in j.get("values", []):
                props = v.get("properties", {})
                if not props.get("systemService") and not v.get("name", "").startswith("AzureCloud."):
                    continue  # aggregates ("AzureCloud" without region…) add nothing
                for p in props.get("addressPrefixes", []):
                    add(p, "Azure", props.get("systemService", ""), props.get("region", ""))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log(f"[cloud] plages Azure indisponibles : {exc}")
        _ranges = out
        return out


def match_range(ranges, ip):
    """Most specific range holding ip (a service-specific range wins a tie), or None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best = None
    for r in ranges:
        if r[0].version == addr.version and addr in r[0]:
            if best is None or r[0].prefixlen > best[0].prefixlen or (
                    r[0].prefixlen == best[0].prefixlen and not best[2] and r[2]):
                best = r
    return best


# --- Discovery ----------------------------------------------------------------------------------

def _is_ip(text):
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        return False


def cloud_domains(hosts):
    """Registrable domains of the scanned names, the most frequent first (max 5)."""
    count = Counter()
    for h in hosts:
        h = h.strip("[].").lower()
        if _is_ip(h) or "." not in h:
            continue
        d = registrable_domain(h)
        if d.rsplit(".", 1)[-1] in INTERNAL_TLDS:
            continue
        count[d] += 1
    return sorted(count, key=lambda d: (-count[d], d))[:5]


def _records(servers, name, qtype):
    from .dns import query
    for host, port in servers:
        try:
            return query(host, port, name, qtype, timeout=3.0)[0]
        except (OSError, ValueError):
            continue
    return []


def _resolves(name):
    try:
        return bool(socket.getaddrinfo(name, None))
    except (socket.gaierror, UnicodeError, OSError):
        return False


def discover_cloud(hosts, log=print, stop=None):
    """Before the scan -> (report, hosts to add on all ports, hosts to add on 443 only)."""
    from .recon import _dns_servers, cname_chain
    rep = {"domains": cloud_domains(hosts), "tenants": [], "services": [], "ips": [], "added": [], "errors": []}
    full, web = [], []
    if not rep["domains"]:
        return rep, full, web
    log(f"[cloud] empreinte cloud et SaaS de {', '.join(rep['domains'])}")
    servers = _dns_servers()
    known = {h.lower() for h in hosts}
    own = set(rep["domains"])
    seen = set()

    def add_service(s):
        k = (s["service"], s["host"], s["source"])
        if k not in seen:
            seen.add(k)
            rep["services"].append(s)

    def add(h, only_web):
        h = (h or "").lower()
        if h and h not in known and _resolves(h):
            known.add(h)
            (web if only_web else full).append(h)
            rep["added"].append(h + (" (443)" if only_web else ""))

    for d in rep["domains"]:
        if stop and stop.is_set():
            break
        recs = [r for t in (15, 16, 2) for r in _records(servers, d, t)]  # MX, TXT, NS
        google = False
        for s in record_services(d, recs):
            add_service(s)
            google = google or (s["service"] == "Google Workspace" and s["source"] == "MX")
        if google:
            rep["tenants"].append({"provider": "Google Workspace", "domain": d, "tenant_id": "", "name": "",
                                   "region": "", "auth": "messagerie Google (MX)", "idp": "", "brand": "",
                                   "domains": []})
        for p in PROBE_NAMES:
            if stop and stop.is_set():
                break
            name = f"{p}.{d}"
            for c in cname_chain(name, servers)[0]:
                m = match_sig("CNAME", c)
                if m:
                    add_service(_svc(m, "CNAME", name, c.rstrip(".")))
                    break
        if stop and stop.is_set():
            break
        try:
            t = microsoft_tenant(d)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            rep["errors"].append(f"{d} : {exc}")
            continue
        if not t:
            continue
        rep["tenants"].append(t)
        log(f"[cloud] {d} : tenant Microsoft {t['tenant_id'] or '-'}, authentification {t['auth'] or '-'}"
            + (f", fournisseur d'identité {t['idp']}" if t["idp"] else ""))
        own |= {registrable_domain(x) for x in t["domains"] if not x.endswith(".onmicrosoft.com")}
    for t in rep["tenants"]:
        for td in [x for x in t["domains"] if not x.endswith(".onmicrosoft.com")][:25]:
            add(td, False)
        if t["idp"]:
            add(t["idp"], registrable_domain(t["idp"]) not in own)
        if t["name"]:
            add(f"{t['name']}.sharepoint.com", True)
            add(f"{t['name']}-my.sharepoint.com", True)
    if rep["added"]:
        log(f"[cloud] {len(rep['added'])} cible(s) ajoutée(s) au scan : {', '.join(rep['added'])}")
    rep["org_domains"] = sorted(own)
    return rep, full, web


def finish_cloud(rep, results, exposures, takeovers, log=print, stop=None):
    """After the scan: CNAME of every scanned name, provider of every public IP, dangling CNAMEs."""
    from .recon import _dns_servers, cname_chain
    if rep is None:
        return rep
    seen = {(s["service"], s["host"], s["source"]) for s in rep["services"]}
    names = []
    for r in results:
        h = r["host"].lower()
        if not _is_ip(h) and h not in names and len(names) < 300:
            names.append(h)
    servers = _dns_servers()
    with ThreadPoolExecutor(16) as pool:
        chains = list(pool.map(lambda n: [] if stop and stop.is_set() else cname_chain(n, servers)[0], names))
    for n, chain in zip(names, chains):
        for c in chain:
            m = match_sig("CNAME", c)
            if m:
                if (m[0], n, "CNAME") not in seen:
                    seen.add((m[0], n, "CNAME"))
                    rep["services"].append(_svc(m, "CNAME", n, c.rstrip(".")))
                break
    for t in takeovers or []:
        rep["services"].append({"service": t["service"], "category": "CNAME orphelin", "source": "takeover",
                                "host": t["host"], "evidence": f"{t['cname']} - {t['reason']}"})
    if exposures is None:
        from .reputation import _resolve_hosts
        exposures = _resolve_hosts(results)
    hosts_of = {}
    for x in exposures:
        if not x.get("internal"):
            lst = hosts_of.setdefault(x["ip"], [])
            lst += [h for h in x["hosts"] if h not in lst]
    for r in results:
        h = r["host"].strip("[]")
        if _is_ip(h) and not is_internal_ip(h):
            hosts_of.setdefault(h, [])
    if hosts_of and not (stop and stop.is_set()):
        ranges = load_ranges(log)
        for ip, hs in hosts_of.items():
            m = match_range(ranges, ip)
            if m:
                rep["ips"].append({"ip": ip, "provider": m[1], "service": m[2], "region": m[3],
                                   "prefix": str(m[0]), "hosts": hs})
        rep["ips"].sort(key=lambda x: (x["provider"], x["ip"]))
    rep["services"].sort(key=lambda s: (s["source"] != "takeover", s["category"], s["service"]))
    if not rep["domains"] and _empty(rep):
        return rep
    by = Counter(x["provider"] for x in rep["ips"])
    log(f"[cloud] {len(rep['tenants'])} tenant(s), {len(rep['services'])} service(s) reconnu(s), IP chez un "
        f"fournisseur cloud : {', '.join(f'{p} {n}' for p, n in sorted(by.items())) or 'aucune'}")
    return rep


# --- Output -------------------------------------------------------------------------------------

def _empty(rep):
    return not rep or not (rep["tenants"] or rep["services"] or rep["ips"] or rep["added"])


def cloud_section(rep):
    if not rep or (not rep["domains"] and _empty(rep)):
        return ""
    e = html.escape
    scope = ", ".join(rep["domains"]) or "IP scannées"
    if _empty(rep):
        return f"<p><b>Empreinte cloud et SaaS</b> ({e(scope)}) : aucun tenant ni service reconnu.</p>"
    out = [f"<details open><summary><b>Empreinte cloud et SaaS</b> - {e(scope)} : {len(rep['tenants'])} tenant(s), "
           f"{len(rep['services'])} service(s), {len(rep['ips'])} IP chez un fournisseur cloud</summary>"]
    if rep["tenants"]:
        out.append("<table><tr><th>Fournisseur</th><th>Domaine</th><th>Tenant</th><th>Région</th><th>Authentification</th>"
                   "<th>Fournisseur d'identité</th><th>Autres domaines du tenant</th></tr>")
        for t in rep["tenants"]:
            tid = f"{t['name']}.onmicrosoft.com {t['tenant_id']}".strip() if t["name"] else t["tenant_id"]
            out.append(f"<tr><td>{e(t['provider'])}</td><td>{e(t['domain'])}</td><td>{e(tid)}</td><td>{e(t['region'])}</td>"
                       f"<td>{e(t['auth'])}</td><td>{e(t['idp'])}</td><td>{e(', '.join(t['domains']))}</td></tr>")
        out.append("</table>")
    if rep["added"]:
        out.append(f"<p>Ajouté(s) au scan : {e(', '.join(rep['added']))}</p>")
    if rep["services"]:
        from .recon import _sev
        out.append("<table><tr><th>Catégorie</th><th>Service</th><th>Nom</th><th>Indice</th><th>Valeur</th></tr>")
        for s in rep["services"]:
            cat = (_sev("haute") + " " if s["source"] == "takeover" else "") + e(s["category"])
            out.append(f"<tr><td>{cat}</td><td>{e(s['service'])}</td><td>{e(s['host'])}</td><td>{e(s['source'])}</td>"
                       f"<td>{e(s['evidence'])}</td></tr>")
        out.append("</table>")
    if rep["ips"]:
        out.append("<table><tr><th>IP</th><th>Fournisseur</th><th>Service</th><th>Région</th><th>Plage</th><th>Noms</th></tr>")
        for x in rep["ips"]:
            out.append(f"<tr><td>{e(x['ip'])}</td><td>{e(x['provider'])}</td><td>{e(x['service'])}</td><td>{e(x['region'])}</td>"
                       f"<td>{e(x['prefix'])}</td><td>{e(', '.join(x['hosts']))}</td></tr>")
        out.append("</table>")
    out.append("</details>")
    return "".join(out)


CLOUD_HEADER = ["type", "provider_or_service", "category_or_service", "host_or_ip", "source_or_region", "detail"]


def cloud_rows(rep):
    if not rep:
        return []
    rows = []
    for t in rep["tenants"]:
        detail = " ; ".join([f"tenant {t['tenant_id']}", t["name"], f"région {t['region']}", f"auth {t['auth']}",
                             f"IdP {t['idp']}"])
        rows.append(["tenant", t["provider"], "", t["domain"], "", f"{detail} ; domaines {' '.join(t['domains'])}"])
    rows += [["service", s["service"], s["category"], s["host"], s["source"], s["evidence"]] for s in rep["services"]]
    rows += [["ip", x["provider"], x["service"], x["ip"], x["region"], f"{x['prefix']} ; {' '.join(x['hosts'])}"]
             for x in rep["ips"]]
    rows += [["ajout", a, "", "", "", "ajouté au scan"] for a in rep["added"]]
    return rows


def write_cloud_csv(rep, path):
    if _empty(rep):
        return
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(CLOUD_HEADER)
        w.writerows(cloud_rows(rep))
