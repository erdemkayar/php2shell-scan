"""Optional passive enrichment (Shodan). Never touches the target; queries a third-party index."""
import ipaddress
import json
import re
import time
import urllib.request

from . import classify as C

VER = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)([^\s;,)\"']*)", re.I)


def parse_shodan_host(doc):
    """Return dict(status, note, php_versions) from a Shodan /shodan/host/{ip} document, or None."""
    vers = set()
    for d in doc.get("data", []):
        for m in VER.finditer(d.get("data", "") or ""):
            vers.add((int(m[1]), int(m[2]), int(m[3]), m[4]))
    if not vers:
        return None
    worst = None
    for v in sorted(vers):
        st, conf, note = C.classify_version(*v)
        if worst is None or C.rank(st) < C.rank(worst[0]):
            worst = (st, note, v)
    v = worst[2]
    return {"status": worst[0], "php_versions": ["%d.%d.%d%s" % v for v in sorted(vers)],
            "note": f"Passive (Shodan banner, may be stale): {worst[1]}"}


def lookup(ip, key, fetch=None, timeout=15):
    # fixed https endpoint; ip is validated by the caller (ipaddress.ip_address)
    fetch = fetch or (lambda url: json.load(urllib.request.urlopen(url, timeout=timeout)))  # noqa: S310
    try:
        return parse_shodan_host(fetch(f"https://api.shodan.io/shodan/host/{ip}?key={key}"))
    except Exception:
        return None


def enrich_assets(assets, key, fetch=None, delay=1.1):
    """Only hosts whose banner status is HIDDEN / NO_PHP and that are public IPs."""
    out = {}
    for a in assets:
        if a["banner_status"] not in ("PHP_VERSION_HIDDEN", "NO_PHP_INDICATOR"):
            continue
        try:
            ip = ipaddress.ip_address(a["host"])
        except ValueError:
            continue
        if not ip.is_global:
            continue
        r = lookup(a["host"], key, fetch)
        if r:
            out[a["host"]] = r
        if fetch is None:
            time.sleep(delay)
    return out
