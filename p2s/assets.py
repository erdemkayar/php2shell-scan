"""Per-host consolidation, grouping and baseline diff."""
import json
import re
from collections import Counter, defaultdict

from . import classify as C

SKIP = {"CLOSED", "OPEN_NO_HTTP", "ERROR"}


def consolidate(results, verify=None, passive=None):
    """Group endpoint results into one asset per host. Worst status wins; host verification overrides banner."""
    verify, passive = verify or {}, passive or {}
    by_host = defaultdict(list)
    for r in results:
        by_host[r["host"]].append(r)
    for h, v in verify.items():
        if v.get("verdict"):
            by_host.setdefault(h, [])
    assets = []
    for host, rs in by_host.items():
        live = [r for r in rs if r["status"] not in SKIP]
        open_only = [r for r in rs if r["status"] == "OPEN_NO_HTTP"]
        if not live and not open_only and host not in verify:
            continue
        labels = {}
        for r in rs:
            labels.update(r.get("labels") or {})
        eps = sorted(live, key=lambda r: (C.rank(r["status"]), r["port"]))
        banner_status = eps[0]["status"] if eps else ("NO_WEB_RESPONSE" if open_only else "NO_PHP_INDICATOR")
        a = {
            "host": host, "labels": labels,
            "ports": sorted({r["port"] for r in live}), "open_ports_no_http": sorted({r["port"] for r in open_only}),
            "banner_status": banner_status,
            "php_versions": sorted({r["php_version"] for r in live if r.get("php_version")}),
            "cms": sorted({c for r in live for c in (r.get("cms_hint") or "").split(",") if c}),
            "servers": sorted({r["server"] for r in live if r.get("server")}),
            "names": sorted({n for r in live for n in ([r.get("sni")] + ((r.get("tls") or {}).get("san") or [])) if n})[:10],
            "dns_names": sorted({n for r in rs for n in (r.get("name"), r.get("sni")) if n}),
            "endpoints": [{k: r.get(k, "") for k in ("port", "scheme", "status", "php_version", "http_status")} for r in eps],
            "confidence": eps[0].get("confidence", "") if eps else "",
            "note": eps[0].get("note", "") if eps else (open_only[0].get("note", "") if open_only else "no web service reached"),
            "verified": None, "passive": passive.get(host),
        }
        a["final_status"] = banner_status
        v = verify.get(host)
        if v and v.get("verdict"):
            a["verified"] = v
            m = {"VULNERABLE": "VERIFIED_VULNERABLE", "VULNERABLE_EOL": "VERIFIED_VULNERABLE",
                 "PATCHED": "VERIFIED_PATCHED", "PATCHED_BACKPORT": "VERIFIED_PATCHED",
                 "PATCHED_RESTART_REQUIRED": "VERIFIED_RESTART_REQUIRED", "NO_PHP_FOUND": "VERIFIED_NO_PHP",
                 "REVIEW": None}
            target = m.get(v["verdict"])
            conflict = _verify_conflict(a, v) if target else ""
            if conflict:  # never let a host check silently hide what the web service itself disclosed
                a["note"] = f"{conflict} Banner status kept; review. (SSH: {v.get('summary', '')})"
            elif target:
                a["final_status"] = target
                a["confidence"] = "verified"
                a["note"] = v.get("summary", a["note"])
        elif passive.get(host) and passive[host].get("status"):
            p = passive[host]
            if C.rank(p["status"]) < C.rank(a["final_status"]):
                a["final_status"] = p["status"]
                a["confidence"] = "low (passive)"
                a["note"] = p.get("note", a["note"])
        a["closure"] = closure(a)
        assets.append(a)
    assets.sort(key=lambda a: (C.rank(a["final_status"]), a["host"]))
    return assets


def closure(a):
    """Where remediation stands for one asset (C.CLOSURE). Closed only on host evidence: patched, running the patched
    code, and (for CLOSED_VERIFIED) a complete --ioc pass without indicators."""
    v = a.get("verified") or {}
    ioc = v.get("ioc")
    if ioc and ioc.get("hits"):
        return "COMPROMISE_SUSPECTED"
    st = a["final_status"]
    if st == "VERIFIED_NO_PHP":
        return "NOT_APPLICABLE"
    if st in ("NO_PHP_INDICATOR", "NO_WEB_RESPONSE"):
        return "NO_PHP_EVIDENCE"
    if st == "VERIFIED_RESTART_REQUIRED":
        return "PENDING_RESTART"
    if C.is_actionable(st):
        mitigated = (v.get("mitigation") or {}).get("state") is True and st != "FPM_EXPOSED"
        return "OPEN_MITIGATED" if mitigated else "OPEN"
    if st == "VERIFIED_PATCHED":
        return "CLOSED_VERIFIED" if ioc and ioc.get("complete") else "CLOSED_IOC_PENDING"
    return "CLOSED_REMOTE"  # PATCHED_BY_BANNER / ORACLE_PATCHED: remote evidence only


def needs_action(a):
    return C.is_actionable(a["final_status"]) or a.get("closure") == "COMPROMISE_SUSPECTED"


SLA_DEFAULT = {"critical": 3, "high": 7, "medium": 14}


def parse_sla(text):
    """'critical=3,high=7,medium=14' -> dict; raises ValueError."""
    out = dict(SLA_DEFAULT)
    for part in filter(None, (x.strip() for x in (text or "").split(","))):
        k, _, v = part.partition("=")
        if k not in SLA_DEFAULT or not v.isdigit():
            raise ValueError(f"invalid --sla entry '{part}' (expected critical|high|medium=<days>)")
        out[k] = int(v)
    return out


def apply_sla(assets, baseline=None, today=None, sla=None):
    """Remediation deadlines for assets that need action. first_seen comes from the baseline when the asset already
    needed action there (the clock does not restart every week); due = first_seen + SLA days of the asset's severity
    (compromise suspected counts as critical). Closed assets keep first_seen and get closed_on."""
    from datetime import date, timedelta
    today = today or date.today()
    sla = sla or SLA_DEFAULT
    old = {a["host"]: a for a in (baseline or [])}
    for a in assets:
        prev = old.get(a["host"], {})
        if not needs_action(a):
            if prev.get("sla", {}).get("first_seen"):
                a["sla"] = {"first_seen": prev["sla"]["first_seen"], "owner": a["labels"].get("owner", ""),
                            "closed_on": prev["sla"].get("closed_on") or today.isoformat()}
            continue
        sev = "critical" if a.get("closure") == "COMPROMISE_SUSPECTED" else C.severity(a["final_status"])
        first = (prev.get("sla") or {}).get("first_seen") if prev and needs_action(prev) else None
        first = date.fromisoformat(first) if first else today
        due = first + timedelta(days=sla.get(sev, sla["medium"]))
        a["sla"] = {"first_seen": first.isoformat(), "due": due.isoformat(), "days": sla.get(sev, sla["medium"]),
                    "overdue_days": max(0, (today - due).days), "owner": a["labels"].get("owner", "")}
    return assets


def _xyz(v):
    m = re.match(r"(\d+\.\d+\.\d+)", v or "")
    return m[1] if m else None


def _verify_conflict(asset, v):
    """Reasons an SSH verdict must not override the banner (empty string = consistent)."""
    banner_has_php = asset["banner_status"] not in ("NO_PHP_INDICATOR", "NO_WEB_RESPONSE")
    if v["verdict"] == "NO_PHP_FOUND" and banner_has_php:
        return ("SSH check found no PHP on the host, but the web service shows PHP "
                "(reverse proxy, container or a different backend?).")
    if v["verdict"].startswith("PATCHED") and asset["banner_status"] == "ORACLE_VULNERABLE":
        return ("The web service's running PHP answered like a pre-fix build (behavioural check), but the host check found "
                "only patched builds: workers not restarted, or another PHP (container/backend) serves this port.")
    if v["verdict"].startswith("PATCHED"):
        seen = {_xyz(x["version"]) for x in v.get("versions", []) if isinstance(x, dict)}
        missing = sorted({_xyz(p) for p in asset["php_versions"]} - seen - {None})
        if missing:
            return f"Web banner shows PHP {', '.join(missing)}, which the SSH check did not find on the host."
    return ""


def summarize(assets):
    c = Counter(a["final_status"] for a in assets)
    cl = Counter(a.get("closure") or closure(a) for a in assets)
    return {"assets": len(assets), "by_status": dict(c), "by_closure": dict(cl),
            "actionable": sum(1 for a in assets if needs_action(a)),
            "verified": sum(1 for a in assets if a["verified"]),
            "overdue": sum(1 for a in assets if (a.get("sla") or {}).get("overdue_days")),
            "max_overdue_days": max([(a.get("sla") or {}).get("overdue_days", 0) for a in assets] + [0])}


def group_table(assets, key="customer"):
    g, act, closed = defaultdict(Counter), Counter(), Counter()
    for a in assets:
        name = a["labels"].get(key, "-")
        g[name][a["final_status"]] += 1
        act[name] += needs_action(a)
        closed[name] += (a.get("closure") or closure(a)) == "CLOSED_VERIFIED"
    rows = []
    for name, c in g.items():
        rows.append({"group": name, "total": sum(c.values()), "actionable": act[name], "closed_verified": closed[name],
                     "by_status": dict(c)})
    rows.sort(key=lambda r: (-r["actionable"], r["group"]))
    return rows


def diff(old_assets, new_assets):
    """Compare two consolidated asset lists keyed by host."""
    o = {a["host"]: a for a in old_assets}
    n = {a["host"]: a for a in new_assets}
    out = {"new_assets": [], "gone_assets": [], "worsened": [], "improved": [], "unchanged": 0, "closure_changes": []}
    for h, a in n.items():
        if h not in o:
            out["new_assets"].append({"host": h, "status": a["final_status"], "labels": a["labels"]})
            continue
        co, cn = o[h].get("closure") or closure(o[h]), a.get("closure") or closure(a)
        if co != cn:  # remediation progress (e.g. OPEN -> PENDING_RESTART -> CLOSED_VERIFIED) even when the status class stays
            out["closure_changes"].append({"host": h, "from": co, "to": cn, "labels": a["labels"]})
        ro, rn = C.rank(o[h]["final_status"]), C.rank(a["final_status"])
        item = {"host": h, "from": o[h]["final_status"], "to": a["final_status"], "labels": a["labels"]}
        ao, an = C.is_actionable(o[h]["final_status"]), C.is_actionable(a["final_status"])
        if an and (not ao or rn < ro):
            out["worsened"].append(item)
        elif ao and (not an or rn > ro):
            out["improved"].append(item)
        else:
            out["unchanged"] += 1
    for h, a in o.items():
        if h not in n:
            out["gone_assets"].append({"host": h, "status": a["final_status"], "labels": a["labels"]})
    return out


def load_assets_any(path):
    """Load a baseline: assets.json written by this tool, or a raw results.jsonl (one JSON object per line)."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        d = None
    if isinstance(d, dict) and "assets" in d:
        return d["assets"]
    if isinstance(d, dict) and "key" in d:  # a single-line results.jsonl
        return consolidate([d])
    rs = []
    for ln in text.splitlines():
        try:
            o = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if isinstance(o, dict) and "key" in o and o.get("status") != "CLOSED":
            rs.append(o)
    if not rs and text.strip():
        raise ValueError(f"{path}: neither an assets.json nor a results.jsonl from this tool")
    return consolidate(rs)
