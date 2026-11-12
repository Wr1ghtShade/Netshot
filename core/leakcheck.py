"""
core/leakcheck.py - LeakCheck Pro API v2: breach records for an email, username, phone, domain...

    GET https://leakcheck.io/api/v2/query/{query}?type=&limit=&offset=
    Header X-API-Key (key "leakcheck" in keys.json, or NETSHOT_KEY_LEAKCHECK)

Answer: {"success", "found", "quota", "result": [row, ...]}. Each row has a "source" object
(name, breach_date, unverified, passwordless, compilation), a "fields" list naming the data
present, and the data itself (email, username, password, first_name, ...). Info-stealer rows
carry "collected" instead of a breach date.

Only the query (email, domain...) is sent to LeakCheck. Use on identities you are allowed to check.

Test from the command line (values are masked unless --show):
    python -m core.leakcheck someone@example.com --type auto
    python -m core.leakcheck example.com --show
"""

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://leakcheck.io/api/v2/query/"
# Types to set explicitly; without type, LeakCheck detects email, username, phone and hash
SEARCH_TYPES = ["auto", "email", "domain", "keyword", "username", "phone", "hash", "phash", "origin", "password"]


def lookup(query, key, qtype="auto", limit=100, offset=0, timeout=60):
    """Query LeakCheck. Returns the decoded answer; raises RuntimeError with a readable message."""
    if not key:
        raise RuntimeError("leakcheck: API key required (key 'leakcheck' in keys.json)")
    query = query.strip()
    if len(query) < 3:
        raise RuntimeError("leakcheck: query must be at least 3 characters")
    params = {"limit": max(1, min(int(limit), 1000)), "offset": max(0, min(int(offset), 2500))}
    if qtype and qtype != "auto":
        params["type"] = qtype
    url = API_URL + urllib.parse.quote(query, safe="") + "?" + urllib.parse.urlencode(params)
    # Key in the header, never in the URL: URLs end up in error messages and logs
    req = urllib.request.Request(url, headers={"User-Agent": "netshot", "Accept": "application/json",
                                               "X-API-Key": key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, body = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read()
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(f"leakcheck: {getattr(exc, 'reason', exc)}") from None
    try:
        data = json.loads(body)
    except ValueError:
        data = {}
    if status != 200 or not data.get("success", False):
        msg = data.get("error") or body[:150].decode(errors="replace").strip()
        if status in (401, 403):
            msg = f"key refused ({msg})"
        elif status == 429:
            msg = f"rate limit or quota reached ({msg})"
        raise RuntimeError(f"leakcheck: HTTP {status}: {msg}")
    return data


def _mask(v):
    s = str(v)
    return s if len(s) <= 2 else s[0] + "*" * (len(s) - 2) + s[-1]


def main():
    import argparse
    from .sources import load_keys
    ap = argparse.ArgumentParser(description="LeakCheck lookup (test)")
    ap.add_argument("query")
    ap.add_argument("--type", default="domain", choices=SEARCH_TYPES)
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--show", action="store_true", help="print values in clear (default: masked)")
    ap.add_argument("--raw", action="store_true", help="print the raw JSON answer")
    args = ap.parse_args()
    try:
        data = lookup(args.query, load_keys().get("leakcheck", ""), args.type, args.limit)
    except RuntimeError as exc:
        sys.exit(str(exc))
    if args.raw:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return
    rows = data.get("result") or []
    print(f"found={data.get('found')} quota={data.get('quota')} rows={len(rows)}")
    print("top-level keys:", sorted(data))
    keys, src_keys = {}, {}
    for r in rows:
        for k, v in r.items():
            keys.setdefault(k, type(v).__name__)
        for k, v in (r.get("source") or {}).items():
            src_keys.setdefault(k, type(v).__name__)
    print("row keys:", keys)
    print("source keys:", src_keys)
    for r in rows[:20]:
        flat = {k: v for k, v in r.items() if k not in ("source", "fields")}
        if not args.show:
            flat = {k: _mask(v) for k, v in flat.items()}
        print("-", (r.get("source") or {}), r.get("fields"), flat)


if __name__ == "__main__":
    main()
