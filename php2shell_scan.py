#!/usr/bin/env python3
"""php2shell-scanner - exposure triage, host verification and remediation tracking for CVE-2026-109618 / CVE-2026-109619
(PHP2Shell).

Passive by default: ordinary HTTP(S) GET requests and banner/cookie fingerprinting. No exploit, memory-exhaustion or
trigger traffic is ever sent. With --oracle, up to 2 small multipart POSTs per endpoint (invalid session id + upload
progress field) are sent: a behavioural check, not an exploit (p2s/oracle.py). Optional SSH / --local verification runs
read-only commands on the host.
Scan only systems you own or have written authorization to assess.
"""
import argparse
import asyncio
import json
import os
import pkgutil
import sys
from datetime import datetime

from p2s import __version__, assets as A, classify as C, engine as E, enrich as EN, evidence as EV, ingest as IN, report as R, \
    verify as V

FORMATS = ["html", "xlsx", "docx", "csv", "json", "findings", "nessus", "sarif", "defectdojo"]
DEFAULT_FORMATS = ["html", "xlsx", "docx", "csv", "json", "findings"]
EXIT_OK, EXIT_ERROR, EXIT_ACTIONABLE, EXIT_INCOMPLETE = 0, 1, 2, 3
BIG_SCAN = 20000

EPILOG = """\
examples:
  # 1) dry run: endpoint count and worst-case duration (no traffic)
  php2shell.pyz -t targets.txt --scope scope.txt --list

  # 2) scan (scope is mandatory)
  php2shell.pyz -t targets.txt --scope scope.txt --authorized -o out/acme --title "ACME"

  # 3) resume an interrupted scan
  php2shell.pyz -t targets.txt --scope scope.txt --authorized -o out/acme --resume

  # 4) weekly re-scan with a diff against last week
  php2shell.pyz -t targets.txt --scope scope.txt --authorized -o out/acme-w43 \\
      --baseline out/acme-w42/assets.json

  # 5) definitive verification over SSH on hosts you can log in to
  php2shell.pyz -t targets.txt --scope scope.txt --authorized -o out/acme --verify --ssh-map ssh_map.txt

  # 6) rebuild the reports without scanning, in Turkish
  php2shell.pyz --report-only -o out/acme --lang tr

target file (one target per line, free-form labels):
  203.0.113.0/24  customer=ACME env=prod owner=ops@acme.example
  198.51.100.10   customer=ACME sni=portal.acme.example ports=443,8443
  https://shop.acme.example/

exit codes:
  0 nothing actionable   2 actionable assets
  3 coverage incomplete: scan interrupted (--resume) or targets skipped (DNS / --max-hosts)
  1 error, invalid target or out-of-scope target

Full guide: php2shell.pyz --guide
"""


class Parser(argparse.ArgumentParser):
    """argparse exits with 2 on usage errors, which would collide with EXIT_ACTIONABLE in automation."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


PROFILES = {
    # first engagement: gentle on the network, everything an auditor or a vulnerability-management import needs
    "pilot": {"rate": 50.0, "concurrency": 50, "per_host": 2, "evidence_pack": True,
              "formats": "html,xlsx,docx,csv,json,findings,nessus"},
}


def build_parser():
    ap = Parser(prog="php2shell.pyz", description=__doc__, epilog=EPILOG,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"php2shell-scanner {__version__}")
    ap.add_argument("--guide", action="store_true", help="print the user guide and exit")
    ap.add_argument("--mcp", action="store_true", help="run as an MCP server (stdio): plan/scan/findings/verify_pack tools for agents")

    g = ap.add_argument_group("targets and scope")
    g.add_argument("-t", "--targets", nargs="*", default=[], metavar="TARGET",
                   help="file(s) and/or inline targets: IP, CIDR, host, host:port, URL")
    g.add_argument("--scope", nargs="*", default=[], metavar="SCOPE",
                   help="approved scope (file or inline): CIDR, IP, hostname, *.domain. "
                        "A single out-of-scope target aborts the run before any traffic")
    g.add_argument("--targets-from", nargs="+", default=[], metavar="FILE",
                   help="other tools' output as targets: nuclei -jsonl or Shodan JSON lines. Scope-checked, scanned and "
                        "verified like any target; the report lists where that tool and this one disagree")
    g.add_argument("--no-scope", action="store_true", help="run without a scope file (a deliberate choice; the report says the scope was not enforced)")
    g.add_argument("--scope-trust-names", action="store_true",
                   help="scan a host approved by name even if it resolves outside the approved IP ranges (e.g. a CDN)")
    g.add_argument("--exclude", nargs="*", default=[], metavar="EXCLUDE", help="IP/CIDR/hostname (or file) to skip")
    g.add_argument("-4", "--ipv4-only", action="store_true", help="scan only the IPv4 addresses of names")
    g.add_argument("--ports", default="80,443,8080,8443,9000", help="comma-separated ports (default: %(default)s)")
    g.add_argument("--max-hosts", type=int, default=65536, help="a single CIDR larger than this is skipped (default: %(default)s)")
    g.add_argument("--authorized", action="store_true", help="confirm you are authorized to scan every target (required)")
    g.add_argument("--yes", action="store_true", help=f"allow scans above {BIG_SCAN} endpoints")

    s = ap.add_argument_group("scanning")
    s.add_argument("--profile", choices=sorted(PROFILES), help="preset; flags given explicitly still win. "
                   "pilot: rate 50/s, 50 workers, 2 connections per host, evidence pack, html/xlsx/docx/csv/json/findings/nessus "
                   "(docs/FIRST_ENGAGEMENT.md)")
    s.add_argument("--rate", type=float, default=300.0, help="new connections per second, all connections included (0 = unlimited; default: %(default)s)")
    s.add_argument("--concurrency", type=int, default=400, help="concurrent workers (default: %(default)s)")
    s.add_argument("--per-host", type=int, default=4, help="max concurrent connections per host (default: %(default)s)")
    s.add_argument("--connect-timeout", type=float, default=3.0, help="TCP connect timeout, s")
    s.add_argument("--http-timeout", type=float, default=8.0, help="HTTP response timeout, s")
    s.add_argument("--tls-timeout", type=float, default=3.0, help="TLS handshake timeout, s")
    s.add_argument("--retries", type=int, default=1, help="retries on timeout/transport error (default: %(default)s)")
    s.add_argument("--deep", action="store_true", help="(the default; accepted for compatibility)")
    s.add_argument("--no-deep", action="store_true",
                   help="turn off discovery. By default up to 10 more GETs per endpoint: a random .php (catch-all guard), "
                        "/index.php, PHP-only application paths, same-host .php links from the page")
    s.add_argument("--oracle", action="store_true",
                   help="ACTIVE behavioural check: up to 2 small multipart POSTs per endpoint (not an exploit). Tells a patched from an "
                        "unpatched RUNNING PHP even with the version hidden or on a distro backport; answers only when the server "
                        "displays PHP warnings. Your authorization must cover active requests")
    s.add_argument("--list", action="store_true", help="dry run: endpoint count and duration estimate, no traffic")
    s.add_argument("--resume", action="store_true", help="resume the interrupted scan in the -o folder")
    s.add_argument("--advisory", metavar="JSON", help="use this advisory file instead of the built-in one (fixed releases, CVEs)")
    s.add_argument("--check-advisory", metavar="JSON", help="validate an advisory file and exit (for a new PHP vulnerability; see docs/ADVISORY.md)")

    o = ap.add_argument_group("output")
    o.add_argument("-o", "--out", help="output folder (required for --resume and --report-only)")
    o.add_argument("--report-only", action="store_true", help="do not scan; rebuild the reports from the results in -o")
    o.add_argument("--baseline", metavar="FILE", help="previous assets.json or results.jsonl to diff against")
    o.add_argument("--sla", default="", metavar="RULES",
                   help="remediation deadline in days, default critical=3,high=7,medium=14. First-seen dates are carried over "
                        "from the baseline; the owner is the owner= label in the target file")
    o.add_argument("--lang", choices=["en", "tr"], default="en", help="report language (default: %(default)s)")
    o.add_argument("--formats", default=",".join(DEFAULT_FORMATS),
                   help="report formats (default: %(default)s; also: nessus, sarif, defectdojo)")
    o.add_argument("--title", default="", help="report title")
    o.add_argument("--group-by", default="customer", help="label used for the group table (default: %(default)s)")
    o.add_argument("--evidence-pack", action="store_true",
                   help="bundle raw results, host checks, reports, scope files, the advisory and the command line into one zip "
                        "with a SHA-256 manifest (for an auditor)")
    o.add_argument("--sign-key", metavar="KEY", help="sign the --evidence-pack manifest with this OpenSSH key (ssh-keygen -Y sign)")
    o.add_argument("--verify-pack", metavar="ZIP", help="verify an evidence pack without scanning (hashes + optional signature)")
    o.add_argument("--allowed-signers", metavar="FILE", help="OpenSSH allowed_signers file for the --verify-pack signature check")
    o.add_argument("--signer-identity", metavar="IDENTITY", help="--verify-pack: signer identity in allowed_signers")

    v = ap.add_argument_group("host verification (read-only)")
    v.add_argument("--verify", action="store_true", help="verify actionable hosts over SSH")
    v.add_argument("--verify-all", action="store_true", help="verify every host in --ssh-map")
    v.add_argument("--ssh-map", metavar="FILE", help="line format: <host> <user@target> [key=~/.ssh/x] [port=22]")
    v.add_argument("--ssh-user", help="default user for hosts not in --ssh-map")
    v.add_argument("--ssh-key", help="default private key")
    v.add_argument("--ssh-accept-new", action="store_true", help="accept the host key on first connection (StrictHostKeyChecking=accept-new)")
    v.add_argument("--ssh-known-hosts", metavar="FILE", help="separate known_hosts file (e.g. per engagement)")
    v.add_argument("--ioc", action="store_true",
                   help="add read-only compromise indicators to the SSH/--local collector: changed PHP files in web roots (path, time, "
                        "size, SHA-256), webshell patterns, PHP code in session/tmp files, shells spawned by PHP workers. No file "
                        "content leaves the host. Your engagement must cover it")
    v.add_argument("--ioc-since", metavar="YYYY-MM-DD",
                   help="--ioc: files changed after this date (default: 30 days before the advisory was published)")
    v.add_argument("--local", metavar="FILE",
                   help="run the same read-only collector on THIS machine and write the result as JSON, without scanning "
                        "(for hosts without SSH access; import it with --import-local). Linux only")
    v.add_argument("--windows-collector", metavar="FILE",
                   help="write the read-only PowerShell collector for Windows/IIS hosts to this file and exit (run it on the "
                        "host, import its output with --import-local)")
    v.add_argument("--import-local", nargs="+", metavar="FILE", default=[],
                   help="import --local / Windows collector results (files or folders) as host verification; the host IP "
                        "must be in scope")

    p = ap.add_argument_group("passive enrichment (third party)")
    p.add_argument("--shodan-key", default=os.environ.get("SHODAN_API_KEY"),
                   help="Shodan lookup for public IPs whose version is hidden. Prefer the SHODAN_API_KEY environment variable "
                        "(a command-line value shows up in shell history and the process list)")
    return ap


def validate(ap, a):
    """Reject inconsistent or unsafe argument combinations up front."""
    if a.rate < 0 or a.concurrency < 1 or a.per_host < 1 or a.retries < 0 or a.max_hosts < 1:
        ap.error("need --rate >= 0, --concurrency/--per-host/--max-hosts >= 1, --retries >= 0")
    if min(a.connect_timeout, a.http_timeout, a.tls_timeout) <= 0:
        ap.error("timeouts must be positive")
    try:
        a.port_list = [int(x) for x in a.ports.split(",") if x.strip()]
    except ValueError:
        ap.error(f"invalid --ports: {a.ports}")
    if not a.port_list or any(not 0 < x < 65536 for x in a.port_list):
        ap.error(f"invalid --ports: {a.ports}")
    a.format_list = [f.strip() for f in a.formats.split(",") if f.strip()]
    bad = set(a.format_list) - set(FORMATS)
    if bad:
        ap.error(f"unknown format(s): {', '.join(sorted(bad))} (valid: {', '.join(FORMATS)})")
    if (a.resume or a.report_only) and not a.out:
        ap.error("--resume and --report-only need -o with an existing output folder")
    if a.scope and a.no_scope:
        ap.error("--scope and --no-scope cannot be used together")
    if a.verify_all and not a.ssh_map:
        ap.error("--verify-all needs --ssh-map")
    if a.ioc_since and not V.DATE_RE.match(a.ioc_since):
        ap.error("--ioc-since must be YYYY-MM-DD")
    if a.allowed_signers and not a.signer_identity:
        ap.error("--allowed-signers needs --signer-identity")
    if a.sign_key and not a.evidence_pack:
        ap.error("--sign-key is only used with --evidence-pack")
    if a.local or a.verify_pack or a.windows_collector or a.check_advisory:
        return
    if not a.scope and not a.no_scope and not a.guide and (not a.report_only or a.verify or a.verify_all or a.import_local):
        ap.error("an approved scope is required: pass --scope <file> (or --no-scope to deliberately run without one)")
    if (a.verify or a.verify_all) and not a.authorized:
        ap.error("SSH verification runs commands on hosts: confirm your authorization with --authorized")
    if (a.ioc or a.ioc_since) and not (a.verify or a.verify_all or a.local):
        ap.error("--ioc is only used with --verify / --verify-all / --local")
    if not a.report_only and not a.targets and not a.targets_from and not a.guide:
        ap.error("no targets: pass IP/CIDR/hosts or a target file with -t")


def read_lines(items):
    lines = []
    for t in items:
        if os.path.isfile(t):
            with open(t, encoding="utf-8") as f:
                lines += f.read().splitlines()
        else:
            lines.append(t)
    return lines


def read_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path, obj):
    """Atomic write: a crash never leaves a half-written verify/meta file behind."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


def _abort(title, items, hint=""):
    print(f"[x] {title} - stopped before sending any traffic:", file=sys.stderr)
    for x in items[:20]:
        print(f"    {x}", file=sys.stderr)
    if len(items) > 20:
        print(f"    ... +{len(items) - 20}", file=sys.stderr)
    if hint:
        print(f"    ({hint})", file=sys.stderr)
    raise SystemExit(EXIT_ERROR)


def plan(a, out):
    """Expand targets, resolve names once (pinned, persisted for --resume), enforce scope, pre-check SSH targets.
    Everything that can refuse the run happens here, before any packet is sent.
    Returns (endpoints, scope_text, scope_check, gaps)."""
    try:
        endpoints, skipped = E.parse_targets(read_lines(a.targets) + external_targets(a), a.port_list, a.max_hosts,
                                             read_lines(a.exclude))
    except E.TargetError as e:
        _abort(f"{len(e.problems)} invalid line(s) in the target/exclude list", e.problems)
    gaps = [f"{t} ({n} hosts > --max-hosts)" for t, n in skipped]
    dns_path = os.path.join(out, "dns.json")
    pinned = read_json(dns_path, None) if a.resume else None
    endpoints, unresolved, resolved = E.resolve_endpoints(endpoints, read_lines(a.exclude), pinned=pinned, ipv4_only=a.ipv4_only)
    if resolved and not a.list:  # a dry run leaves nothing on disk
        os.makedirs(out, exist_ok=True)
        write_json(dns_path, resolved)
    gaps += [f"{n} (DNS unresolved)" for n in unresolved]
    sc = E.load_scope(read_lines(a.scope))
    if sc is None:
        check = "NOT enforced (--no-scope)"
        print("[!] --no-scope: targets are NOT checked against an approved scope", file=sys.stderr)
    else:
        endpoints, violations, scope_gaps = E.apply_scope(endpoints, sc, a.scope_trust_names)
        if violations:
            hint = ""
            if any("->" in v for v in violations) and not a.scope_trust_names:
                hint = ("the name is in scope but resolves to an IP outside the approved ranges, or the scope lists only names: "
                        "add the IP to the scope, or pass --scope-trust-names if the owner approved the name")
            _abort(f"{len(violations)} target(s) outside the approved scope", violations, hint)
        gaps += scope_gaps
        check = f"enforced ({', '.join(os.path.basename(x) if os.path.isfile(x) else x for x in a.scope)})" + (
            " + names trusted" if a.scope_trust_names else "")
        print(f"[*] all targets are inside the approved scope ({check})", file=sys.stderr)
    if a.verify or a.verify_all:
        ssh_preflight(a, sc)
    for g in gaps:
        print(f"[!] not scanned: {g}", file=sys.stderr)
    if not endpoints:
        raise SystemExit("[x] no endpoint left to scan (no targets, unresolved, out of scope or all excluded)")
    hosts = len({e["host"] for e in endpoints})
    return endpoints, f"{hosts} hosts / {', '.join(map(str, sorted({e['port'] for e in endpoints})))}", check, gaps


def external_targets(a):
    lines = []
    for f in a.targets_from:
        try:
            got, kind = IN.target_lines(open(f, encoding="utf-8").read())
        except (OSError, ValueError) as e:
            raise SystemExit(f"[x] --targets-from {f}: {e}") from None
        print(f"[*] {f}: {len(got)} target(s) from {kind} output (scope check applies)", file=sys.stderr)
        lines += got
    return lines


def load_ssh_map_or_exit(a):
    try:
        return V.load_ssh_map(a.ssh_map)
    except (OSError, ValueError) as e:
        raise SystemExit(f"[x] --ssh-map: {e}") from None


def ssh_preflight(a, sc):
    """SSH runs commands on hosts: every ssh-map entry (its key and an IP-literal target) must be in scope.
    Checked before the scan starts, so a bad map never costs a finished scan its reports."""
    smap = load_ssh_map_or_exit(a)
    if sc is None:
        return smap
    bad = []
    for key, ent in smap.items():
        tgt = V.ssh_target_host(ent["target"])
        if not E.in_scope(key, sc):
            bad.append(key)
        elif E._is_ip(tgt) and not E.in_scope(tgt, sc):
            bad.append(f"{key} (ssh target {tgt})")
        elif not E._is_ip(tgt) and tgt != key:
            print(f"[!] ssh target '{tgt}' is an alias/hostname: its IP scope check depends on ssh_config ({key})", file=sys.stderr)
    if bad:
        _abort("SSH verification targets outside the approved scope", bad)
    return smap


def scan(a, endpoints, opts, results_path, out):
    """Run the scan. Returns (stats, complete, missing)."""
    store = E.Store(results_path, a.resume)
    stats = {"seconds": 0, "total": 0}
    try:
        stats = asyncio.run(E.run_scan(endpoints, opts, store))
    except KeyboardInterrupt:
        print(f"\n[!] interrupted. To continue, add to the same command: --resume -o {out}", file=sys.stderr)
    finally:
        store.close()
    missing = sum(1 for e in endpoints if E.endpoint_key(e) not in store.done)
    return stats, missing == 0, missing


def _ssh_entry_for(asset, smap, name_hosts):
    """The ssh-map entry to use for one asset, or None. Matched by the asset IP, else by a DNS name it was scanned
    under; a name match is rewritten to connect to THIS asset's IP (HostKeyAlias keeps host-key checking by name)."""
    for key in [asset["host"]] + list(asset.get("dns_names", [])):
        ent = smap.get(key)
        if not ent:
            continue
        if key == asset["host"]:
            return key, ent
        user, _, tgt = ent["target"].rpartition("@")
        if tgt == key:
            return key, dict(ent, target=f"{user}@{asset['host']}" if user else asset["host"], alias=key)
        if not E._is_ip(tgt) and len(name_hosts.get(key, ())) > 1:
            print(f"[!] ssh-map '{key}' -> alias '{tgt}' maps to {len(name_hosts[key])} IPs; which machine to connect to is "
                  f"ambiguous, {asset['host']} not verified (key the entry by IP)", file=sys.stderr)
            return key, None
        return key, ent
    return None, None


def _verification_plan(a, assets, smap):
    """asset IP -> ssh entry for every host that will be verified."""
    name_hosts = {}
    for x in assets:
        for n in x.get("dns_names", []):
            name_hosts.setdefault(n, set()).add(x["host"])
    plan_, used = {}, set()
    for x in assets:
        key, ent = _ssh_entry_for(x, smap, name_hosts)
        if key:
            used.add(key)
        wanted = a.verify_all or C.is_actionable(x["final_status"])
        if ent and wanted:
            plan_[x["host"]] = ent
        elif not key and wanted and not a.verify_all and (a.ssh_user or a.ssh_key):
            plan_[x["host"]] = {"target": f"{a.ssh_user}@{x['host']}" if a.ssh_user else x["host"], "key": a.ssh_key, "port": 22}
    if a.verify_all:
        for k, ent in smap.items():
            if k in used:
                continue
            if E._is_ip(k):
                plan_[k] = ent  # host without a web service: verified on its own
            else:
                print(f"[!] ssh-map entry '{k}' matched no scanned asset, skipped", file=sys.stderr)
    return plan_


def run_verification(a, assets, verify, vpath):
    """SSH-verify the planned hosts and store verdicts under the asset IP so they merge with the web results."""
    smap = ssh_preflight(a, E.load_scope(read_lines(a.scope)))
    plan_ = _verification_plan(a, assets, smap)
    print(f"[*] SSH verification: {len(plan_)} host(s)", file=sys.stderr)
    if a.ssh_known_hosts:
        V.SSH_OPTS[:] = ["-o", f"UserKnownHostsFile={os.path.expanduser(a.ssh_known_hosts)}"]
    verify.update(V.verify_hosts(sorted(plan_), plan_, a.ssh_user, a.ssh_key, a.ssh_accept_new))
    write_json(vpath, verify)
    for h in sorted(plan_):
        r = verify[h]
        print(f"    {h}: {r['verdict'] or 'FAILED'} - {r['summary']}", file=sys.stderr)


def default_ioc_since():
    """Advisory publication date minus 30 days: exploitation can predate disclosure."""
    from datetime import date, timedelta
    pub = C.ADVISORY.get("published", "")
    try:
        return (date.fromisoformat(pub) - timedelta(days=30)).isoformat()
    except ValueError:
        return (date.today() - timedelta(days=60)).isoformat()


def run_local(a):
    """--local: collect on this machine, write the JSON, scan nothing."""
    if not sys.platform.startswith("linux"):
        raise SystemExit("[x] --local runs on a Linux host (the collector uses /proc, dpkg/rpm and Linux tools); use --windows-collector on Windows")
    print("[*] running the read-only collector on this host" + (f" (+IoC since {V.IOC_SINCE})" if V.IOC_SINCE else ""), file=sys.stderr)
    doc = V.run_local()
    write_json(a.local, doc)
    rec, ips = V.load_local(doc)
    print(f"[*] {a.local}: {rec['verdict']} - {rec['summary']}", file=sys.stderr)
    print(f"    IPs: {', '.join(ips) or '-'}  (on the scanner: --import-local {os.path.basename(a.local)})", file=sys.stderr)
    return EXIT_OK


def import_local(a, results, verify, vpath):
    """Merge --local results into verify.json under the scanned asset IP they belong to (scope-checked)."""
    sc = E.load_scope(read_lines(a.scope))
    scanned = {r["host"] for r in results}
    files = []
    for x in a.import_local:
        files += sorted(os.path.join(x, f) for f in os.listdir(x) if f.endswith(".json")) if os.path.isdir(x) else [x]
    for f in files:
        try:
            rec, ips = V.load_local(read_json(f, None))
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"[!] {f}: not imported ({e})", file=sys.stderr)
            continue
        host = next((ip for ip in ips if ip in scanned), None) or next(
            (ip for ip in ips if sc is None or E.in_scope(ip, sc)), None)
        if not host or (sc is not None and not E.in_scope(host, sc)):
            print(f"[!] {f}: its IPs ({', '.join(ips) or '-'}) are not in the approved scope, not imported", file=sys.stderr)
            continue
        verify[host] = dict(rec, file=os.path.basename(f))
        print(f"    {host}: {rec['verdict'] or 'FAILED'} - {rec['summary']} (--local {os.path.basename(f)})", file=sys.stderr)
    write_json(vpath, verify)


def print_summary(summary, diff, files, results_path, complete, missing, out, gaps=(), assets_for_print=(), lang="en"):
    print("\n=== Summary ===")
    for st in sorted(summary["by_status"], key=C.rank):
        print(f"{C.status_label(st, lang):<58}{summary['by_status'][st]}")
    print(f"\nassets: {summary['assets']} | need action: {summary['actionable']} | verified on host: {summary['verified']}")
    dis = IN.disagreements(assets_for_print)
    if dis:
        print(f"[!] disagreement with an external tool: {len(dis)} asset(s) (it reported a finding, this tool found patched / no PHP); listed in report.html")
    if summary.get("overdue"):
        print(f"[!] SLA exceeded: {summary['overdue']} asset(s) (oldest {summary['max_overdue_days']} day(s) overdue)")
    cl = summary.get("by_closure") or {}
    if cl:
        print("closure: " + " | ".join(f"{C.closure_label(c, lang)}: {cl[c]}" for c in C.CLOSURE if cl.get(c)))
    if diff:
        print(f"vs baseline: +{len(diff['new_assets'])} new, -{len(diff['gone_assets'])} gone, "
              f"{len(diff['worsened'])} worsened, {len(diff['improved'])} improved")
    print("Reports:\n  " + "\n  ".join(files + [results_path]))
    print("Banner results are triage: verify LIKELY / VERIFY / HIDDEN statuses on the host (--verify / --local).")
    if complete is False:
        print(f"[!] INCOMPLETE SCAN: {missing} endpoint(s) not scanned, reports are marked partial. Continue: --resume -o {out}")
    elif complete is None:
        print("[!] COMPLETENESS UNKNOWN: no meta.json; the reports are marked accordingly.")
    if gaps:
        print(f"[!] COVERAGE GAPS: {len(gaps)} target(s) not scanned: {', '.join(gaps[:10])}")


def main(argv=None):
    ap = build_parser()
    pre, _ = ap.parse_known_args(argv)
    if pre.profile:  # profile values become the defaults, so any flag given on the command line still wins
        ap.set_defaults(**PROFILES[pre.profile])
    a = ap.parse_args(argv)
    if a.guide:
        sys.stdout.write(pkgutil.get_data("p2s", "guide.md").decode("utf-8"))
        return EXIT_OK
    if a.mcp:
        from p2s import mcp
        mcp.serve()
        return EXIT_OK
    validate(ap, a)
    if a.advisory:
        errs, _ = C.validate_advisory(read_json(a.advisory, None))
        if errs:
            ap.error(f"--advisory {a.advisory}: " + "; ".join(errs))
        C.load_advisory(a.advisory)
    if a.oracle and C.ADVISORY.get("oracle") != "session-write":
        ap.error(f"--oracle is a validated behavioural check for PHP2Shell only; it does not apply to advisory "
                 f"'{C.ADVISORY.get('id')}' (the advisory has no \"oracle\")")
    if a.ioc or a.ioc_since:
        V.IOC_SINCE = a.ioc_since or default_ioc_since()
    try:
        sla_rules = A.parse_sla(a.sla)
    except ValueError as e:
        ap.error(str(e))
    if a.check_advisory:
        try:
            adv = read_json(a.check_advisory, None)
        except (OSError, ValueError) as e:
            raise SystemExit(f"[x] {a.check_advisory}: {e}") from None
        errs, warns = C.validate_advisory(adv)
        for x in errs:
            print(f"[x] {x}")
        for x in warns:
            print(f"[!] {x}")
        if not errs:
            print(f"[*] {a.check_advisory}: valid ({adv['id']}, {', '.join(adv['cves'])}; fixed: "
                  f"{', '.join(adv['fixed'].values())}). Use it with: --advisory {a.check_advisory}")
        return EXIT_ERROR if errs else EXIT_OK
    if a.local:
        return run_local(a)
    if a.windows_collector:
        script = pkgutil.get_data("p2s", "collect_windows.ps1").decode("utf-8").replace("@VERSION@", __version__)
        with open(a.windows_collector, "w", encoding="utf-8-sig", newline="\r\n") as f:  # BOM: PowerShell 5.1 reads UTF-8 only with it
            f.write(script)
        print(f"[*] {a.windows_collector} written. On the Windows host (as Administrator):\n"
              f"    powershell -NoProfile -ExecutionPolicy Bypass -File {os.path.basename(a.windows_collector)} -Out host.json [-Ioc]",
              file=sys.stderr)
        return EXIT_OK
    if a.verify_pack:
        ok, lines = EV.verify(a.verify_pack, a.allowed_signers, a.signer_identity)
        print("\n".join(lines))
        print("[*] evidence pack VERIFIED" if ok else "[x] evidence pack FAILED verification")
        return EXIT_OK if ok else EXIT_ERROR
    out = a.out or os.path.join("php2shell_out", datetime.now().strftime("%Y%m%d-%H%M%S"))
    results_path = os.path.join(out, "results.jsonl")
    opts = {"concurrency": a.concurrency, "per_host": a.per_host, "rate": a.rate, "connect_timeout": a.connect_timeout,
            "http_timeout": a.http_timeout, "tls_timeout": a.tls_timeout, "deep": not a.no_deep, "retries": a.retries,
            "oracle": a.oracle}
    stats, scope, scope_check, complete, missing, gaps = {"seconds": 0}, "", "", None, 0, []

    if not a.report_only:
        endpoints, scope, scope_check, gaps = plan(a, out)
        opts["allowed_ports"] = {e["port"] for e in endpoints}  # redirects never leave the scanned port set
        est = E.estimate_seconds(len(endpoints), opts)
        print(f"[*] {len(endpoints)} endpoint(s), {scope}; worst-case duration ~{est/60:.1f} min "
              f"(rate {a.rate:g}/s, {a.concurrency} workers)", file=sys.stderr)
        if a.oracle:
            print("[!] --oracle: up to 2 small multipart POSTs will be sent to every endpoint that answers HTTP (active request)",
                  file=sys.stderr)
        if a.list:
            return EXIT_OK
        if not a.authorized:
            raise SystemExit("Scan refused: confirm with --authorized that you are authorized to scan every target.")
        if len(endpoints) > BIG_SCAN and not a.yes:
            raise SystemExit(f"more than {BIG_SCAN} endpoints: add --yes to confirm.")
        if not a.resume:  # a fresh scan must not inherit last run's host verdicts or enrichment
            for n in ("verify.json", "passive.json", "meta.json"):  # (dns.json is rewritten by plan())
                pth = os.path.join(out, n)
                if os.path.exists(pth):
                    os.replace(pth, pth + ".prev")
        stats, complete, missing = scan(a, endpoints, opts, results_path, out)
    elif not os.path.exists(results_path):
        raise SystemExit(f"{results_path} not found")

    counts = {}
    results = E.load_results(results_path, skip_closed=True, stats=counts)
    open_n = sum(1 for r in results if r["status"] != "ERROR")
    vpath, ppath, mpath = (os.path.join(out, n) for n in ("verify.json", "passive.json", "meta.json"))
    verify, passive, old = read_json(vpath, {}), read_json(ppath, {}), read_json(mpath, {})

    if a.shodan_key:
        print("[*] Shodan enrichment (third-party lookup): public hosts with a hidden version", file=sys.stderr)
        passive.update(EN.enrich_assets(A.consolidate(results, verify, passive), a.shodan_key))
        write_json(ppath, passive)
    if a.verify or a.verify_all:
        run_verification(a, A.consolidate(results, verify, passive), verify, vpath)
    if a.import_local:
        import_local(a, results, verify, vpath)
    assets = A.consolidate(results, verify, passive)
    base_assets = A.load_assets_any(a.baseline) if a.baseline else None
    A.apply_sla(assets, base_assets, sla=sla_rules)
    summary, groups = A.summarize(assets), A.group_table(assets, a.group_by)
    diff = A.diff(base_assets, assets) if a.baseline else None

    if a.report_only:  # keep what the scan recorded; no meta.json (e.g. kill -9) -> completeness unknown
        complete, missing, gaps = old.get("complete"), old.get("missing", 0), old.get("gaps", [])
    meta = {"title": a.title or old.get("title", ""), "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "scope": scope or old.get("scope", ""), "scope_check": scope_check or old.get("scope_check", ""),
            "complete": complete, "missing": missing, "gaps": gaps, "endpoints": counts["total"], "open": open_n,
            "duration": f"{stats['seconds']/60:.1f} min" if stats.get("seconds") else old.get("duration", ""),
            "baseline": os.path.basename(a.baseline) if a.baseline else "",
            "advisory": f"{C.ADVISORY.get('id', '')} {C.ADVISORY.get('published', '')}".strip(),
            "oracle": any("oracle" in r for r in results) or bool(old.get("oracle") and a.report_only),
            "tool_version": __version__}
    os.makedirs(out, exist_ok=True)
    write_json(mpath, meta)
    files = R.write_all(out, results, assets, summary, groups, meta, diff, a.format_list, a.lang)
    if a.evidence_pack:
        path, manifest = EV.build(out, [x for x in a.scope if os.path.isfile(x)], ["php2shell.pyz"] + list(argv or sys.argv[1:]),
                                  a.sign_key)
        files.append(path)
        print(f"[*] evidence pack: {path} ({len(manifest['files'])} files" + (", signed" if a.sign_key else "") + ")", file=sys.stderr)
    print_summary(summary, diff, files, results_path, complete, missing, out, gaps, assets, a.lang)
    if complete is not True or gaps:
        return EXIT_INCOMPLETE
    return EXIT_ACTIONABLE if summary["actionable"] else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
