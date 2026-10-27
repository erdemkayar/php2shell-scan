"""End-to-end test against a REAL PHP installation and a REAL sshd (disposable Linux box / CI container, as root).

Prerequisites: php-cli (+ distro changelogs under /usr/share/doc/php*), openssh-server. The test:
  1. serves PHP with `php -S` on 127.0.0.1 (version disclosed) and 127.0.0.2 (version hidden, session cookie)
  2. runs a temporary sshd on 127.0.0.1:2222 with a throw-away key
  3. scans, then verifies over SSH in three host states:
       a) as installed                         -> verdict from the real package changelog
       b) a PHP worker running a replaced binary -> VERIFIED_RESTART_REQUIRED (only if (a) was patched)
       c) changelog evidence hidden            -> VERIFIED_VULNERABLE
     State (c) temporarily renames changelog files and restores them in a finally block.
Run: sudo python3 tests/e2e_real_php.py
"""
import glob, gzip, json, os, shutil, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = [sys.executable, os.path.join(ROOT, "php2shell_scan.py")]
FAIL = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  ({detail})" if detail else ""), flush=True)
    if not cond:
        FAIL.append(name)


def run(args, **kw):
    p = subprocess.run(CLI + args, capture_output=True, text=True, timeout=300, **kw)
    return p.returncode, p.stdout + p.stderr


def final(out_dir):
    return {a["host"]: a["final_status"] for a in json.load(open(os.path.join(out_dir, "assets.json")))["assets"]}


def main():
    if os.geteuid() != 0 or not shutil.which("php") or not os.path.exists("/usr/sbin/sshd"):
        print("SKIP: needs root, php and /usr/sbin/sshd")
        return 0
    w = tempfile.mkdtemp(prefix="p2s-e2e-")
    procs, moved = [], []
    try:
        # --- web: real PHP built-in server
        doc = os.path.join(w, "doc")
        os.makedirs(doc)
        open(os.path.join(doc, "index.php"), "w").write("<?php session_start(); echo 'hello';")
        procs.append(subprocess.Popen(["php", "-d", "expose_php=1", "-S", "127.0.0.1:8300", "-t", doc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        procs.append(subprocess.Popen(["php", "-d", "expose_php=0", "-S", "127.0.0.2:8300", "-t", doc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        # --oracle target: version hidden, PHP warnings displayed (the only setup in which the behavioural check answers)
        procs.append(subprocess.Popen(["php", "-d", "expose_php=0", "-d", "display_errors=1", "-d", "display_startup_errors=1",
                                       "-S", "127.0.0.4:8300", "-t", doc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        # --- ssh: temporary sshd + key
        key, hostkey, ak = os.path.join(w, "id"), os.path.join(w, "hostkey"), os.path.join(w, "authorized_keys")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostkey], check=True)
        shutil.copy(key + ".pub", ak)
        os.chmod(ak, 0o600)
        os.makedirs("/run/sshd", exist_ok=True)
        procs.append(subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-p", "2222", "-h", hostkey, "-o", "ListenAddress=127.0.0.1",
                                       "-o", f"AuthorizedKeysFile={ak}", "-o", "PermitRootLogin=prohibit-password",
                                       "-o", "PasswordAuthentication=no", "-o", "UsePAM=no", "-o", "StrictModes=no", "-o", f"PidFile={w}/sshd.pid"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(1.5)
        smap = os.path.join(w, "ssh_map.txt")
        open(smap, "w").write(f"127.0.0.1 root@127.0.0.1 key={key} port=2222\n127.0.0.2 root@127.0.0.1 key={key} port=2222\n")
        php_v = subprocess.run(["php", "-r", "echo PHP_VERSION;"], capture_output=True, text=True).stdout
        print(f"real PHP_VERSION={php_v}")

        out = os.path.join(w, "out")
        base = ["--report-only", "-o", out, "--verify-all", "--ssh-map", smap, "--ssh-accept-new", "--authorized", "--scope", "127.0.0.0/29",
                "--ssh-known-hosts", os.path.join(w, "known_hosts"), "--formats", "json,html", "--ioc"]
        # 1) scan (banner only)
        rc, log = run(["-t", "127.0.0.1", "127.0.0.2", "--ports", "8300", "--authorized", "--scope", "127.0.0.0/29",
                       "-o", out, "--formats", "json"])
        res = {r["host"]: r for r in (json.loads(l) for l in open(os.path.join(out, "results.jsonl")))}
        r1, r2 = res.get("127.0.0.1", {}), res.get("127.0.0.2", {})
        check("banner: real PHP version read", r1.get("php_version", "").startswith(php_v), f"{r1.get('status')} {r1.get('php_version')}")
        check("banner: hidden version detected via session cookie", r2.get("status") == "PHP_VERSION_HIDDEN", f"{r2.get('status')} {r2.get('indicators')}")
        changelog_has_fix = any(b"CVE-2026-109619" in gzip.open(c).read() for c in glob.glob("/usr/share/doc/php*/changelog.Debian.gz"))
        # 1b) --oracle on the real distro build: the running code, not the version string, decides
        oout = os.path.join(w, "oracle")
        rc, log = run(["-t", "127.0.0.4", "--ports", "8300", "--authorized", "--scope", "127.0.0.0/29", "--oracle", "-o", oout,
                       "--formats", "json"])
        ro = next(json.loads(l) for l in open(os.path.join(oout, "results.jsonl")))
        exp = "ORACLE_PATCHED" if changelog_has_fix else "ORACLE_VULNERABLE"
        check(f"oracle on real PHP {php_v} -> {exp} (changelog fix present={changelog_has_fix})", ro.get("status") == exp,
              f"{ro.get('status')} {ro.get('oracle')}")
        # 2a) verify as installed
        rc, log = run(base)
        print("   " + "\n   ".join(l for l in log.splitlines() if l.startswith("    1")))
        f = final(out)
        exp = "VERIFIED_PATCHED" if changelog_has_fix else "VERIFIED_VULNERABLE"
        check(f"verify as installed -> {exp} (changelog fix present={changelog_has_fix})",
              f.get("127.0.0.1") == exp and f.get("127.0.0.2") == exp, str(f))
        v = json.load(open(os.path.join(out, "verify.json"))).get("127.0.0.1", {})
        check("--ioc over SSH: collected as root, mitigation evaluated", (v.get("ioc") or {}).get("priv") == "root"
              and "mitigation" in v, f"ioc={ {k: (v.get('ioc') or {}).get(k) for k in ('priv', 'hits')} } mit={(v.get('mitigation') or {}).get('state')}")
        # 2b) restart required: a 'php-fpm' process whose binary was replaced on disk
        if changelog_has_fix:
            stale = os.path.join(w, "php-fpm-e2e")
            shutil.copy(shutil.which("php"), stale)
            p = subprocess.Popen([stale, "-S", "127.0.0.3:8301"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(p)
            time.sleep(0.5)
            os.remove(stale)  # /proc/<pid>/exe now ends with '(deleted)'
            rc, log = run(base)
            f = final(out)
            check("replaced binary still running -> VERIFIED_RESTART_REQUIRED", f.get("127.0.0.1") == "VERIFIED_RESTART_REQUIRED", str(f))
            p.kill()
            p.wait()
        # 2c) no backport evidence -> vulnerable
        for c in sorted({os.path.realpath(x) for x in glob.glob("/usr/share/doc/php*/changelog.Debian.gz")}):
            os.rename(c, c + ".p2s-e2e")  # doc dirs are often symlinks to one package dir: dedupe by real path
            moved.append(c)
        rc, log = run(base)
        f = final(out)
        check("changelog evidence absent -> VERIFIED_VULNERABLE", f.get("127.0.0.1") == "VERIFIED_VULNERABLE", str(f))
        check("actionable exit code 2", rc == 2, f"rc={rc}")
        html = open(os.path.join(out, "report.html"), encoding="utf-8").read()
        check("HTML report carries host verification text", "Unpatched:" in html, "")
    finally:
        for c in moved:
            if os.path.exists(c + ".p2s-e2e"):
                os.rename(c + ".p2s-e2e", c)
        for p in procs:
            p.kill()
        shutil.rmtree(w, ignore_errors=True)
    print("\n" + ("ALL PASSED" if not FAIL else f"{len(FAIL)} FAILED: {FAIL}"))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
