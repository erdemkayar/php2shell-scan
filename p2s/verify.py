"""Optional second stage: SSH verification of PHP version / backport / restart state.

The remote script runs read-only commands: `-v` of every PHP binary it finds (also `frankenphp version`),
package queries, changelog greps for the advisory's CVE ids, /proc exe/maps (replaced binaries still running),
`apache2ctl -M`, and `docker exec <container> php -v`. It creates/changes no files, but it does execute those
binaries and `docker exec` leaves an entry in the Docker event log: get the host owner's approval for that."""
import concurrent.futures as cf
import os
import re
import subprocess
from datetime import datetime, timezone

from . import __version__
from . import classify as C

REMOTE_SCRIPT = r"""
S=""; [ "$(id -u)" != 0 ] && S="sudo -n"
echo "HOST=$(hostname)"
( . /etc/os-release 2>/dev/null; echo "OS=$PRETTY_NAME" )
fp() { find "$@" \( -type f -o -type l \) \( -name php -o -name 'php[0-9]*' -o -name 'php-fpm*' -o -name 'php-cgi*' \
        -o -name 'lsphp*' -o -name frankenphp \) 2>/dev/null; }
BINS=$({ fp /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -maxdepth 1
  fp /opt -maxdepth 7               # cPanel ea-phpXX, CloudLinux alt-php, Remi SCL, Plesk
  fp /usr/local/lsws -maxdepth 5    # LiteSpeed lsphp
  for d in /usr/local/php*; do [ -d "$d" ] && fp "$d" -maxdepth 3; done   # DirectAdmin
} | sort -u)                        # kept in memory: the collector never writes on the host
[ "$(printf '%s\n' "$BINS" | grep -c .)" -gt 300 ] && echo "TRUNCATED=binaries"
printf '%s\n' "$BINS" | grep . | head -300 | while read -r b; do
  case "$b" in *frankenphp) v=$(timeout 5 "$b" version 2>/dev/null | head -1);; *) v=$(timeout 5 "$b" -v 2>/dev/null | head -1);; esac
  echo "BIN=$b|$v"
done
dpkg-query -W -f='${db:Status-Abbrev}|${Package} ${Version}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null | awk -F'|' '$1 ~ /^ii/ {print "PKG=" $2}' | head -80
rpm -qa --qf 'PKG=%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | grep -E '^PKG=(php|ea-php|rh-php|mod_php)' | head -80
CVRE='CVE-[0-9]{4}-[0-9]{4,}([_-][0-9]{4,})*'
for f in $(for x in /usr/share/doc/php*/changelog.Debian.gz /usr/share/doc/php*/changelog.gz; do [ -f "$x" ] && readlink -f "$x"; done | sort -u); do
  echo "BP=$(basename "$(dirname "$f")")|$(zgrep -hoE "$CVRE" "$f" 2>/dev/null | grep -E '@CVE_IDS@' | sort -u | tr '\n' ',')"
done
for p in $(rpm -qa 2>/dev/null | grep -E '^(php|rh-php)[^ ]*-(common|cli)' | head -20); do
  echo "BPR=$(rpm -q --qf '%{VERSION}' "$p")|$(rpm -q --changelog "$p" 2>/dev/null | grep -oE "$CVRE" | grep -E '@CVE_IDS@' | sort -u | tr '\n' ',')"
done
(apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null) | grep -i php | sed 's/^/APACHE_MOD=/' | head -3
PIDS=$(pgrep -f 'php-fpm|php-cgi|frankenphp|lsphp' 2>/dev/null)
[ "$(printf '%s\n' "$PIDS" | grep -c .)" -gt 500 ] && echo "TRUNCATED=processes"
for pid in $(printf '%s\n' "$PIDS" | head -500); do
  exe=$(readlink /proc/$pid/exe 2>/dev/null); case "$exe" in *"(deleted)"*) echo "STALE=$pid:$exe";; esac
done
for pid in $(pgrep -f 'apache2|httpd' 2>/dev/null | head -50); do
  grep -q 'libphp.*(deleted)' /proc/$pid/maps 2>/dev/null && echo "STALE=$pid:libphp(deleted)"
done
if command -v docker >/dev/null 2>&1; then
  CTS=$($S docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}' 2>/dev/null)
  [ "$(printf '%s\n' "$CTS" | grep -c .)" -gt 200 ] && echo "TRUNCATED=containers"
  for c in $(printf '%s\n' "$CTS" | head -200); do
    id=${c%%|*}; rest=${c#*|}
    v=$($S timeout 10 docker exec "$id" sh -c 'php -v 2>/dev/null | head -1' 2>/dev/null)
    [ -n "$v" ] && echo "CT=$rest|$v"
  done
fi
{ hostname -I 2>/dev/null || ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1; } | tr ' ' '\n' \
  | grep -E '^[0-9A-Fa-f.:]+$' | head -64 | sed 's/^/IP=/'
# interim-mitigation inputs: these keys from every php.ini set and its scan dir (load order), FPM pools, Apache php_flag
INIK='session\.upload_progress\.enabled|file_uploads|enable_post_data_reading|session\.use_strict_mode|session\.save_handler|display_errors|display_startup_errors'
for ini in /etc/php/*/*/php.ini /etc/php.ini /usr/local/etc/php/php.ini /etc/opt/remi/php*/php.ini /opt/cpanel/ea-php*/root/etc/php.ini \
           /opt/alt/php*/etc/php.ini /opt/plesk/php/*/etc/php.ini /usr/local/php*/lib/php.ini /usr/local/lsws/lsphp*/etc/php/*/litespeed/php.ini; do
  d=$(dirname "$ini")
  [ -f "$ini" ] || [ -d "$d/conf.d" ] || [ -d "$d/php.d" ] || continue
  echo "INISET=$ini"
  for f in "$ini" $(ls "$d"/conf.d/*.ini "$d"/php.d/*.ini "$d"/php.conf.d/*.ini 2>/dev/null | sort); do
    grep -hE "^[[:space:]]*($INIK)[[:space:]]*=" "$f" 2>/dev/null | sed "s|^|INI=$ini\||"
  done
done | head -800
grep -HE "^[[:space:]]*php(_admin)?_(value|flag)\[($INIK)\]" /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf \
  /usr/local/etc/php-fpm.d/*.conf /etc/opt/remi/php*/php-fpm.d/*.conf /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf \
  /opt/plesk/php/*/etc/php-fpm.d/*.conf 2>/dev/null | head -200 | sed 's/^/POOL=/'
grep -rhE "php_(admin_)?(flag|value)[[:space:]]+($INIK)" /etc/apache2 /etc/httpd 2>/dev/null | head -50 | sed 's/^[[:space:]]*/APACHEINI=/'
"""

# Opt-in (--ioc) read-only compromise indicators. Reports paths, timestamps, sizes, SHA-256 and process lines only:
# no file content leaves the host. Timestamps can be forged, so ctime (not settable by touch) is checked too.
REMOTE_IOC = r"""
SINCE='@SINCE@'
if [ "$(id -u)" = 0 ]; then P=""; echo "IOC_PRIV=root"
elif sudo -n true 2>/dev/null; then P="sudo -n"; echo "IOC_PRIV=root"
else P=""; echo "IOC_PRIV=user"; fi
echo "IOC_SINCE=$SINCE"
ROOTS=$( { grep -rhoE '^[[:space:]]*DocumentRoot[[:space:]]+"?[^" ]+' /etc/apache2 /etc/httpd 2>/dev/null | awk '{print $2}' | tr -d '"'
           grep -rhoE '^[[:space:]]*root[[:space:]]+[^;]+' /etc/nginx 2>/dev/null | awk '{print $2}'
           ls -d /var/www /srv/www /usr/share/nginx/html /home/*/public_html 2>/dev/null; } | sort -u | head -50)
for r in $ROOTS; do [ -d "$r" ] && echo "IOC_ROOT=$r"; done
RECENT=$(for r in $ROOTS; do [ -d "$r" ] && $P find "$r" -xdev -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[0-9]' \
  -o -iname '*.phar' -o -name '.user.ini' -o -name '.htaccess' \) \( -newermt "$SINCE" -o -newerct "$SINCE" \) 2>/dev/null; done \
  | sort -u | head -501)  # roots nest (/var/www and /var/www/html): one line per file
[ "$(printf '%s\n' "$RECENT" | grep -c .)" -gt 500 ] && echo "TRUNCATED=ioc_recent"
printf '%s\n' "$RECENT" | grep . | head -500 | while IFS= read -r f; do
  echo "IOC_RECENT=$f|$($P stat -c '%y|%s' "$f" 2>/dev/null)|$($P sha256sum "$f" 2>/dev/null | cut -c1-64)"
done
SHELLRE='(eval|assert)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(POST|GET|REQUEST|COOKIE|SERVER))|(system|passthru|shell_exec|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|preg_replace[[:space:]]*\([^)]*/e'
printf '%s\n' "$RECENT" | grep . | head -500 | tr '\n' '\0' | $P xargs -0 -r grep -lE "$SHELLRE" 2>/dev/null | head -50 | sed 's/^/IOC_SHELL=/'
for s in $(ls -d /var/lib/php/sessions /var/lib/php/session /var/lib/php*/sessions /tmp /var/tmp /dev/shm 2>/dev/null | sort -u); do
  $P find "$s" -maxdepth 2 -xdev -type f -size -1024k \( -name 'sess_*' -o -iname '*.php' -o -iname '*.phtml' \) -print0 2>/dev/null
done | sort -zu | head -z -n 5000 | $P xargs -0 -r grep -lE '<\?php|<\?=|eval[[:space:]]*\(|base64_decode[[:space:]]*\(' 2>/dev/null | head -50 | sed 's/^/IOC_SESS=/'
# workers by process NAME (-x): a command line merely mentioning apache2 (apache2ctl, tail of a log) is not a worker
for p in $(pgrep -x 'apache2|httpd|php-fpm[0-9.]*|php-cgi[0-9.]*|lsphp[0-9]*|frankenphp' 2>/dev/null | head -500); do
  ps --ppid "$p" -o ppid=,pid=,comm=,args= 2>/dev/null; done \
  | awk '$3 ~ /^(sh|bash|dash|zsh|ash|nc|ncat|netcat|socat|python[0-9.]*|perl|ruby|curl|wget|php|busybox|telnet)$/' \
  | head -50 | cut -c1-200 | sed 's/^ */IOC_CHILD=/'
"""
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
IOC_SINCE = None  # set by the CLI (--ioc): collect compromise indicators changed since this date

PHP_V = re.compile(r"(?<![A-Za-z])PHP\s+v?(\d+)\.(\d+)\.(\d+)(\S*)")
SYSTEM_BIN = ("/usr/bin/", "/usr/sbin/")  # only binaries installed by the distro package manager live here


def remote_script(ioc_since=None):
    """Remote collector with the advisory's CVE numbers baked into the changelog filter (+ the --ioc section)."""
    ioc_since = ioc_since or IOC_SINCE
    s = REMOTE_SCRIPT.replace("@CVE_IDS@", "|".join(re.escape(c.rsplit("-", 1)[-1]) for c in C.CVES))
    if ioc_since:
        if not DATE_RE.match(ioc_since):  # interpolated into a shell script: only a plain date may pass
            raise ValueError(f"--ioc-since must be YYYY-MM-DD, got {ioc_since!r}")
        s += REMOTE_IOC.replace("@SINCE@", ioc_since)
    return s + 'echo "DONE=1"\n'


def expand_cve_tokens(tokens):
    """'CVE-2026-109618_109619' (a combined Debian patch name) -> both ids."""
    out = set()
    for t in tokens:
        m = re.match(r"CVE-(\d{4})-(\d+(?:[_-]\d+)*)$", t.strip())
        if m:
            out.update(f"CVE-{m[1]}-{n}" for n in re.split(r"[_-]", m[2]))
    return sorted(out)


def _upstream(version):
    """'2:8.3.6-0ubuntu0.24.04.13' / '8.2.13-1.el9_4' -> ('8.3', '8.3.6')."""
    m = re.match(r"(?:\d+:)?(\d+)\.(\d+)\.(\d+)", version or "")
    return (f"{m[1]}.{m[2]}", f"{m[1]}.{m[2]}.{m[3]}") if m else (None, None)


def parse_output(text):
    d = {"bins": [], "pkgs": [], "backport": {}, "apache_mod": [], "stale": [], "containers": [], "os": "", "host": "",
         "done": False, "ips": [], "ini_sets": [], "ini": [], "pools": [], "apache_ini": [], "ioc": None}
    for ln in text.splitlines():
        k, sep, v = ln.partition("=")
        if not sep:
            continue
        if k.startswith("IOC_"):
            _parse_ioc(d, k, v)
        elif k == "IP":
            d["ips"].append(v.strip())
        elif k == "INISET":
            d["ini_sets"].append(v)
        elif k == "INI":
            iset, _, raw = v.partition("|")
            d["ini"].append((iset, raw))
        elif k == "POOL":
            d["pools"].append(v)
        elif k == "APACHEINI":
            d["apache_ini"].append(v.strip())
        elif k == "BIN":
            path, _, ver = v.partition("|")
            d["bins"].append({"path": path, "banner": ver})
        elif k == "PKG":
            name, _, ver = v.partition(" ")
            if ver.strip():
                d["pkgs"].append((name, ver.strip()))
        elif k in ("BP", "BPR"):
            src, _, ids = v.partition("|")
            m = re.match(r"php(\d+\.\d+)", src) if k == "BP" else None
            branch = m[1] if m else _upstream(src)[0]
            cves = [c for c in expand_cve_tokens(ids.split(",")) if c in C.CVES]
            if branch and cves:
                d["backport"].setdefault(branch, set()).update(cves)
        elif k == "APACHE_MOD":
            d["apache_mod"].append(v)
        elif k == "STALE":
            d["stale"].append(v)
        elif k == "CT":
            name, image, ver = (v.split("|") + ["", "", ""])[:3]
            d["containers"].append({"name": name, "image": image, "banner": ver})
        elif k == "OS":
            d["os"] = v
        elif k == "HOST":
            d["host"] = v
        elif k == "TRUNCATED" and v == "ioc_recent":
            if d["ioc"] is not None:
                d["ioc"]["truncated"] = True
        elif k == "TRUNCATED":
            d.setdefault("truncated", set()).add(v)
        elif k == "DONE":
            d["done"] = True
    return d


def _parse_ioc(d, k, v):
    ioc = d["ioc"] = d["ioc"] or {"since": "", "priv": "", "roots": [], "recent": [], "shells": [], "sessions": [], "children": []}
    if k == "IOC_SINCE":
        ioc["since"] = v
    elif k == "IOC_PRIV":
        ioc["priv"] = v
    elif k == "IOC_ROOT":
        ioc["roots"].append(v)
    elif k == "IOC_RECENT":
        path, mtime, size, sha = (v.rsplit("|", 3) + ["", "", ""])[:4] if v.count("|") >= 3 else (v, "", "", "")
        ioc["recent"].append({"path": path, "mtime": mtime[:19], "size": size, "sha256": sha})
    elif k == "IOC_SHELL":
        ioc["shells"].append(v)
    elif k == "IOC_SESS":
        ioc["sessions"].append(v)
    elif k == "IOC_CHILD":
        ioc["children"].append(v)


TRUE_VALUES = {"1", "on", "true", "yes"}
INI_DEFAULTS = {"session.upload_progress.enabled": "1", "file_uploads": "1", "enable_post_data_reading": "1"}
MITIGATING = ("session.upload_progress.enabled", "file_uploads", "enable_post_data_reading")  # any of these off


def _ini_value(raw):
    """'session.upload_progress.enabled = Off ; note' -> ('session.upload_progress.enabled', '0')."""
    key, _, val = raw.partition("=")
    val = val.split(";", 1)[0].strip().strip("\"'").lower()
    return key.strip(), ("1" if val in TRUE_VALUES else "0" if val in {"0", "off", "false", "no", "none", ""} else val)


def _pool_set(pool_file, sets):
    """php.ini set a pool file belongs to: /etc/php/8.3/fpm/pool.d/www.conf -> /etc/php/8.3/fpm/php.ini."""
    parent = os.path.dirname(os.path.dirname(pool_file))
    for cand in (parent + "/php.ini", parent + "/php/php.ini"):  # /usr/local/etc/php-fpm.d -> /usr/local/etc/php/php.ini
        if cand in sets:
            return cand
    return parent + "/php.ini"


def _blocked_by(values):
    return next((k for k in MITIGATING if values.get(k, INI_DEFAULTS[k]) == "0"), "")


def mitigation(d):
    """Interim mitigation state of the web-facing SAPIs (CLI sets ignored).
    state True = every web SAPI and FPM pool has upload progress / file uploads / POST reading off; False = at least
    one does not; None = no ini set found. .user.ini / .htaccess overrides (PHP_INI_PERDIR) are not read."""
    sets = {s: {} for s in d.get("ini_sets", [])}
    for iset, raw in d.get("ini", []):
        k, v = _ini_value(raw)
        sets.setdefault(iset, {})[k] = v  # emitted in load order: last one wins
    pools = {}
    for ln in d.get("pools", []):
        f, _, raw = ln.partition(":")
        m = re.search(r"php(_admin)?_(?:value|flag)\[([^\]]+)\]\s*=\s*(.*)", raw)
        if m:
            k, v = _ini_value(f"{m[2]}={m[3]}")
            pools.setdefault(f, {})[k] = v
    out, notes = {}, []
    for iset, vals in sets.items():
        if "/cli/" in iset:
            continue
        own = {f: p for f, p in pools.items() if _pool_set(f, sets) == iset}
        out[iset] = {"blocked_by": _blocked_by(vals), "settings": vals,
                     "pools": {f: _blocked_by(dict(vals, **p)) for f, p in own.items()}}
    for ln in d.get("apache_ini", []):
        if re.search(r"session\.upload_progress\.enabled\s+(on|1|true)\b", ln, re.I):
            notes.append(f"Apache config re-enables upload progress: {ln[:120]}")
    if not out:
        return {"state": None, "sets": {}, "notes": ["no php.ini found for a web SAPI"]}
    ok = all(s["blocked_by"] and all(s["pools"].values()) for s in out.values()) and not notes
    return {"state": ok, "sets": out, "notes": notes}


def ioc_summary(ioc):
    """(hits, complete, text) for a parsed --ioc section; hits are the indicators that need incident review."""
    if not ioc:
        return [], False, ""
    hits = ([f"webshell pattern: {p}" for p in ioc["shells"]] + [f"PHP code in session/tmp file: {p}" for p in ioc["sessions"]]
            + [f"shell/network tool spawned by a PHP worker: {c}" for c in ioc["children"]])
    complete = ioc["priv"] == "root" and not ioc.get("truncated")
    text = (f"IoC since {ioc['since']}: {len(hits)} hit(s), {len(ioc['recent'])} PHP file(s) changed in {len(ioc['roots'])} web root(s)"
            + ("" if complete else " (incomplete: " + ("not root" if ioc["priv"] != "root" else "file list truncated") + ")"))
    return hits, complete, text


def _builds(d):
    """Every PHP build found: (version tuple, suffix, source label, is_system_binary). Unversioned ones -> None."""
    out, unknown = [], []
    for b in d["bins"]:
        m = PHP_V.search(b["banner"] or "")
        if m:
            out.append(((int(m[1]), int(m[2]), int(m[3])), m[4], f"bin:{b['path']}", b["path"].startswith(SYSTEM_BIN)))
        else:
            unknown.append(f"bin:{b['path']} (version unreadable)")
    for c in d["containers"]:
        m = PHP_V.search(c["banner"] or "")
        if m:
            out.append(((int(m[1]), int(m[2]), int(m[3])), m[4], f"container:{c['name']}", False))
    distro_pkgs = [n for n, _ in d["pkgs"] if n.startswith(("php", "libapache2-mod-php", "mod_php"))]
    if d["apache_mod"] and not any(n.startswith(("libapache2-mod-php", "php")) for n in distro_pkgs):
        unknown.append("Apache mod_php loaded, version not tied to a package")
    return out, unknown, distro_pkgs


def verdict(d):
    """(verdict, summary, versions[{version, source, patched, how}]) from parsed remote output.
    A distro changelog only vouches for the binaries of THAT package: same branch, same upstream version as the
    installed package, installed under /usr/bin or /usr/sbin. /usr/local, /opt and containers never inherit it."""
    builds, unknown, distro_pkgs = _builds(d)
    if not builds and not unknown and not distro_pkgs:
        return "NO_PHP_FOUND", "No PHP binaries, packages, Apache module or PHP containers found.", []
    pkg_versions = {}
    for _name, ver in d["pkgs"]:
        br, up = _upstream(ver)
        if br:
            pkg_versions.setdefault(br, set()).add(up)
    versions = []
    for (maj, mi, pa), suf, src, system in builds:
        st = C.classify_version(maj, mi, pa, suf)[0]
        br, ver = f"{maj}.{mi}", f"{maj}.{mi}.{pa}"
        if st == "PATCHED_BY_BANNER":
            patched, how = True, "version >= fixed"
        elif system and set(C.CVES) <= d["backport"].get(br, set()) and ver in pkg_versions.get(br, set()):
            patched, how = True, f"php{br} package changelog lists {', '.join(C.CVES)}"
        else:
            patched, how = False, "below fixed version, no backport evidence for this build"
        versions.append({"version": f"{ver}{suf}", "source": src, "patched": patched, "how": how})
    bad = [v for v in versions if not v["patched"]]
    if bad:
        eol = any(tuple(int(x) for x in v["version"].split(".")[:2]) < C.EOL_BELOW for v in bad)
        return ("VULNERABLE_EOL" if eol else "VULNERABLE"),\
            "Unpatched: " + "; ".join(f"{v['version']} ({v['source']})" for v in bad), versions
    if d.get("truncated"):
        unknown.append(f"collector limit reached ({', '.join(sorted(d['truncated']))}): verdict would be partial")
    if unknown or not versions:
        return "REVIEW", "Manual review needed: " + "; ".join(unknown or ["PHP packages present but no runnable binary found"]), versions
    if d["stale"]:
        return "PATCHED_RESTART_REQUIRED", "Patched on disk but running processes use the old binary: " + "; ".join(d["stale"]), versions
    backport = any("changelog" in v["how"] for v in versions)
    return ("PATCHED_BACKPORT" if backport else "PATCHED"), "All PHP builds patched: " + "; ".join(
        f"{v['version']} ({v['source']}, {v['how']})" for v in versions), versions


def record(output, source, checked_at=None):
    """verify.json record from raw collector output (SSH or --local)."""
    d = parse_output(output)
    v, summary, vers = verdict(d)
    mit = mitigation(d)
    hits, ioc_complete, ioc_text = ioc_summary(d["ioc"])
    if mit["state"] is True and v and v.startswith("VULNERABLE"):
        summary += "; interim mitigation active in every web SAPI (upload progress / file uploads off)"
    if ioc_text:
        summary += f"; {ioc_text}"
    rec = {"verdict": v, "summary": summary, "versions": vers, "os": d["os"], "hostname": d["host"], "ips": d["ips"],
           "containers": d["containers"], "stale": d["stale"], "source": source,
           "backport_cves": {b: sorted(c) for b, c in d["backport"].items()}, "mitigation": mit, "checked_at": checked_at or now()}
    if d["ioc"] is not None:
        rec["ioc"] = dict(d["ioc"], hits=hits, complete=ioc_complete)
    return rec


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


SSH_OPTS = []  # extra ssh -o options set by the CLI (e.g. a per-engagement known_hosts file)


SSH_TIMEOUT = 300  # the collector runs `-v` on up to 300 binaries (5 s cap each) and `docker exec` per container


def ssh_run(target, key=None, accept_new=False, port=22, timeout=None, host_key_alias=None):
    timeout = timeout or SSH_TIMEOUT
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", str(port)] + SSH_OPTS
    if host_key_alias:  # connecting to a pinned IP: check the host key recorded under the DNS name
        cmd += ["-o", f"HostKeyAlias={host_key_alias}"]
    if accept_new:
        cmd += ["-o", "StrictHostKeyChecking=accept-new"]
    if key:
        cmd += ["-o", "IdentitiesOnly=yes", "-i", os.path.expanduser(key)]
    cmd += [target, "bash -s"]
    p = subprocess.run(cmd, input=remote_script(), capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr.strip().splitlines()[-1] if p.stderr.strip() else ""


def run_local(timeout=None):
    """--local: the same read-only collector on THIS machine. Returns the JSON document `--import-local` reads."""
    p = subprocess.run(["bash", "-s"], input=remote_script(), capture_output=True, text=True, timeout=timeout or SSH_TIMEOUT)
    if "DONE=1" not in p.stdout:
        raise RuntimeError(f"collector failed (rc={p.returncode}): {p.stderr.strip()[-300:]}")
    return {"format": "php2shell.local/1", "tool_version": __version__,
            "collected_at": now(), "ioc_since": IOC_SINCE, "output": p.stdout}


def load_local(doc):
    """(record, ips) from a --local JSON document; raises ValueError on anything else."""
    if not isinstance(doc, dict) or doc.get("format") != "php2shell.local/1" or "DONE=1" not in str(doc.get("output", "")):
        raise ValueError("not a php2shell --local result (format php2shell.local/1)")
    rec = record(doc["output"], "local", doc.get("collected_at"))
    return rec, rec["ips"]


def load_ssh_map(path):
    """Lines: <host> <user@target> [key=/path] [port=22]   (# comments). Raises ValueError naming the bad line."""
    m = {}
    if not path:
        return m
    with open(path, encoding="utf-8") as f:
        for no, ln in enumerate(f, 1):
            ln = ln.split("#")[0].strip()
            if not ln:
                continue
            t = ln.split()
            ent = {"target": t[1] if len(t) > 1 else t[0], "key": None, "port": 22}
            if ent["target"].startswith("-") or t[0].startswith("-"):
                raise ValueError(f"ssh-map line {no}: host/target must not start with '-'")
            for x in t[2:]:
                if x.startswith("key="):
                    ent["key"] = os.path.expanduser(x[4:])
                elif x.startswith("port=") and x[5:].isdigit() and 0 < int(x[5:]) < 65536:
                    ent["port"] = int(x[5:])
                else:
                    raise ValueError(f"ssh-map line {no}: unknown or invalid option '{x}'")
            m[t[0]] = ent
    return m


def ssh_target_host(target):
    """'user@1.2.3.4' -> '1.2.3.4'; 'alias' -> 'alias' (resolved by ~/.ssh/config, cannot be scope-checked here)."""
    return target.rsplit("@", 1)[-1]


def verify_hosts(hosts, ssh_map, default_user=None, default_key=None, accept_new=False, workers=8, runner=ssh_run):
    out = {}

    def one(h):
        ent = ssh_map.get(h) or ({"target": f"{default_user}@{h}" if default_user else h, "key": default_key, "port": 22})
        try:
            extra = {"host_key_alias": ent["alias"]} if ent.get("alias") else {}
            rc, so, se = runner(ent["target"], ent["key"], accept_new, ent["port"], **extra)
        except Exception as e:  # noqa: BLE001
            return h, {"verdict": None, "summary": f"SSH failed: {type(e).__name__}: {e}", "error": True, "checked_at": now()}
        if rc != 0 or "DONE=1" not in so:
            return h, {"verdict": None, "summary": f"SSH failed (rc={rc}): {se or 'no output'}", "error": True, "checked_at": now()}
        return h, record(so, "ssh")

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for h, r in ex.map(one, hosts):
            out[h] = r
    return out
