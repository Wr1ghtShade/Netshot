"""
core/stealth.py - stealth mode (--stealth): the slowest, quietest scan NetShot can run, to stay
under the thresholds of an IDS / WAF / SOC during an authorised test of their detection. Same
behaviour as stealth.go (netshot-go):

- one check at a time, a random pause before every TCP connection (--stealth-delay, 3-8 s by
  default) and at least the longest pause between two page loads;
- hosts and ports tested in random order (no sequential sweep of a host);
- one ordinary browser User-Agent (Chrome on Windows) instead of the headless browser's own, which
  says "HeadlessChrome"; no bot User-Agent;
- every request that is not a plain visit is dropped: folders, sensitive files, WAF probe, UDP, TLS
  analysis, IPv6 parity, certificate pivot.

The lookups that never reach the target (enrichment, reputation, cloud footprint, crt.sh, RDAP)
stay on.
"""

import random

DEFAULT_DELAY = (3.0, 8.0)


def parse_stealth_delay(text):
    """"3-8" or "5" (seconds) -> (min, max)."""
    text = (text or "").strip()
    if not text:
        return DEFAULT_DELAY
    lo, _, hi = text.partition("-")
    try:
        a, b = float(lo), float(hi or lo)
    except ValueError:
        raise ValueError(f"délai furtif invalide {text!r} (exemple : 3-8)") from None
    if a < 0 or b < a:
        raise ValueError(f"délai furtif invalide {text!r} (exemple : 3-8)")
    return a, b


def pick(delay):
    return random.uniform(*delay) if delay[1] > delay[0] else delay[0]


def fmt_duration(seconds):
    if seconds < 60:
        return f"{int(seconds)} s"
    if seconds < 3600:
        return f"{int(seconds // 60)} min"
    return f"{int(seconds // 3600)} h {int(seconds % 3600 // 60):02d} min"


def estimate(checks, delay):
    """Rough duration of the TCP checks alone, in seconds."""
    return checks * (delay[0] + delay[1]) / 2


def apply_stealth(args, browser_uas, log=print):
    """Turns args into their quiet version and says what changed."""
    delay = getattr(args, "stealth_delay", None) or DEFAULT_DELAY
    args.stealth_delay = delay
    args.concurrency = 1
    args.delay = max(getattr(args, "delay", 0) or 0, delay[1])
    off = []
    for attr, label, empty in (("dirs", "dossiers", None), ("files", "fichiers sensibles", None),
                               ("waf_probe", "sonde WAF", False), ("udp", "UDP", False),
                               ("tls", "analyse TLS", False), ("ipv6_parity", "parité IPv6", False)):
        if getattr(args, attr, None):
            setattr(args, attr, empty)
            off.append(label)
    args.user_agents = [("default", browser_uas["chrome-windows"])]
    msg = (f"[furtif] 1 vérification à la fois, pause aléatoire de {delay[0]:g} s à {delay[1]:g} s avant chaque "
           f"connexion, ordre aléatoire, User-Agent Chrome Windows")
    if off:
        msg += " ; désactivés : " + ", ".join(off)
    log(msg)
