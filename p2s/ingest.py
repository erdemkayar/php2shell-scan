"""--targets-from: other tools' output as targets ("second opinion").

nuclei JSONL (`nuclei -jsonl`) and Shodan JSON lines (`shodan download` / `shodan parse`) become ordinary target lines,
labelled with what the other tool said, so they go through the same scope check, scan and host verification. The report
then lists where the other tool and this one disagree (e.g. a nuclei version match on a distro backport). Nothing is
trusted from the file except host, port and scheme."""
import json
import re
from urllib.parse import urlparse

LABEL = "external"


def _target(url_or_host, port=None, scheme=None):
    if "://" not in url_or_host and url_or_host.count(":") > 1 and not url_or_host.startswith("["):
        url_or_host = f"[{url_or_host}]"  # bare IPv6 (nuclei "ip", Shodan "ip_str")
    u = urlparse(url_or_host if "://" in url_or_host else f"{scheme or 'http'}://{url_or_host}")
    if not u.hostname:
        return None
    host = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
    p = u.port or port or (443 if u.scheme == "https" else 80)
    return f"{u.scheme}://{host}:{p}/"


def parse(text):
    """[(target_line_without_labels, label_value)] from nuclei JSONL or Shodan JSON lines; raises ValueError otherwise."""
    out, kind = [], None
    for no, ln in enumerate(text.splitlines(), 1):
        ln = ln.strip()
        if not ln:
            continue
        try:
            d = json.loads(ln)
        except json.JSONDecodeError:
            raise ValueError(f"line {no}: not JSON (expected nuclei -jsonl or Shodan JSON lines)") from None
        if "template-id" in d:
            kind = "nuclei"
            t = _target(d.get("matched-at") or d.get("host") or d.get("ip") or "", d.get("port") and int(d["port"]))
            label = f"nuclei:{d['template-id']}"
        elif "ip_str" in d and "port" in d:
            kind = "shodan"
            t = _target(d["ip_str"], int(d["port"]), "https" if "ssl" in d else "http")  # key presence: the ssl dict may be empty
            vers = sorted(set(re.findall(r"PHP/(\d+\.\d+\.\d+)", d.get("data", "") or "")))
            label = "shodan" + (f":PHP/{vers[0]}" if vers else "")
        else:
            raise ValueError(f"line {no}: neither a nuclei result (template-id) nor a Shodan banner (ip_str, port)")
        if t:
            out.append((t, re.sub(r"[^\w.:/+-]", "_", label)[:80]))
    if not out:
        raise ValueError("no targets found")
    return out, kind


def target_lines(text):
    """Deduplicated target lines with the external label (several findings for one endpoint are joined)."""
    pairs, kind = parse(text)
    merged = {}
    for t, label in pairs:
        merged.setdefault(t, [])
        if label not in merged[t]:
            merged[t].append(label)
    return [f"{t} {LABEL}={'+'.join(ls)}" for t, ls in merged.items()], kind


def disagreements(assets):
    """Assets an external tool flagged where this tool, with host or behavioural evidence, says otherwise."""
    out = []
    for a in assets:
        ext = a.get("labels", {}).get(LABEL)
        if not ext:
            continue
        mine = a["final_status"]
        if mine in ("VERIFIED_PATCHED", "ORACLE_PATCHED", "VERIFIED_NO_PHP", "PATCHED_BY_BANNER", "NO_PHP_INDICATOR"):
            out.append({"host": a["host"], "external": ext, "status": mine, "closure": a.get("closure", "")})
    return out
