"""--oracle lab: real PHP builds in Docker, scanned by the real CLI. Every case states the status it must produce.

What it pins down (reproduced 2026-10-23, see p2s/oracle.py):
  * pre-fix 8.1-8.5 print 3/3 session warnings, fixed 8.2.35/8.3.36/8.4.27/8.5.12 print 2/3 (mod_php and FPM)
  * Ubuntu 24.04 php8.3 8.3.6-0maysync1 (pre-fix) vs 8.3.6-0ubuntu0.24.04.13 (backport): same version, 3/3 vs 2/3
  * silent (no verdict, banner status kept) when display_errors or display_startup_errors is off (distro production
    php.ini), session.upload_progress.enabled=0, use_strict_mode=1, a phpredis handler, or no PHP at all
  * a custom session.name is learned from the endpoint's Set-Cookie (PHPSESSID alone: 0/3)
  * --full also: Ubuntu Apache upgraded in place to the backport but not restarted stays ORACLE_VULNERABLE, also after
    `apache2ctl -k graceful` (the parent keeps the deleted libphp mapped); only a stop/start loads the fix
Needs Docker; pulls official php images and builds the Ubuntu (and with --full the phpredis) images from tests/oracle_lab/.
Docker Hub rate limits: P2S_LAB_REGISTRY=public.ecr.aws/docker/library/ (or mirror.gcr.io/library/) uses a mirror.
Run: python3 tests/oracle_lab.py [--full]
"""
import json, os, shutil, socket, subprocess, sys, tempfile, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REG = os.environ.get("P2S_LAB_REGISTRY", "")
BASE_PORT = 18100
UBU_INI = "/etc/php/8.3/apache2/conf.d/99-lab.ini"
OFF_INI = "/usr/local/etc/php/conf.d/99-lab.ini"
SHOW = "display_errors=1\ndisplay_startup_errors=1\n"
UBU_OLD, UBU_NEW = "8.3.6-0maysync1", "8.3.6-0ubuntu0.24.04.13"
DOCROOTS = {
    "plain": {"index.php": "<?php echo 'lab';\n"},
    "session": {"index.php": "<?php session_start(); echo 'lab';\n"},
    "static": {"index.html": "<html>static</html>\n"},
    "linked": {"index.html": '<html><a href="portal/search.php?q=1">search</a></html>\n', "portal/search.php": "<?php echo 'r';\n"},
}
FAIL = []


def case(name, image, expect, ini="", ini_path=OFF_INI, doc="plain", oracle="", build=None, fpm=False, needs=None, cport=80):
    return dict(name=name, image=image, expect=expect, ini=ini, ini_path=ini_path, doc=doc, oracle=oracle, build=build,
                fpm=fpm, needs=needs, cport=cport)


def cases(full):
    off = lambda v: f"{REG}php:{v}-apache"
    out = []
    for bad, good in (("8.2.34", "8.2.35"), ("8.3.35", "8.3.36"), ("8.4.26", "8.4.27"), ("8.5.11", "8.5.12")):
        out.append(case(f"upstream {bad} pre-fix", off(bad), "ORACLE_VULNERABLE", oracle="VULNERABLE"))
        out.append(case(f"upstream {good} fixed", off(good), "ORACLE_PATCHED", oracle="PATCHED"))
    out += [
        case("EOL 8.1", off("8.1"), "ORACLE_VULNERABLE", oracle="VULNERABLE"),
        # PHP 7 defaults display_startup_errors to Off (8.0 turned it On): silent unless shown, other warning wording
        case("EOL 7.4 defaults", off("7.4"), "VERIFY_DISTRO_BACKPORT", oracle="SILENT"),
        case("EOL 7.4 warnings shown", off("7.4"), "ORACLE_VULNERABLE", ini=SHOW, oracle="VULNERABLE"),
        case("8.5.11 FPM behind nginx", f"{REG}php:8.5.11-fpm", "ORACLE_VULNERABLE", oracle="VULNERABLE", fpm=True),
        case("8.5.11 display_errors=0", off("8.5.11"), "LIKELY_VULNERABLE", ini="display_errors=0\n", oracle="SILENT"),
        case("8.5.11 display_startup_errors=0", off("8.5.11"), "LIKELY_VULNERABLE",
             ini="display_errors=1\ndisplay_startup_errors=0\n", oracle="SILENT"),
        case("8.5.11 upload_progress off", off("8.5.11"), "LIKELY_VULNERABLE",
             ini="session.upload_progress.enabled=0\n", oracle="SILENT"),
        case("8.5.11 use_strict_mode=1", off("8.5.11"), "LIKELY_VULNERABLE", ini="session.use_strict_mode=1\n", oracle="SILENT"),
        case("8.5.11 custom session.name learned", off("8.5.11"), "ORACLE_VULNERABLE", ini="session.name=LABSID\n",
             doc="session", oracle="VULNERABLE"),
        case("no PHP (static site)", off("8.5.11"), "NO_PHP_INDICATOR", doc="static", oracle="SILENT"),
        case("static front page, PHP behind a link", off("8.5.11"), "ORACLE_VULNERABLE", doc="linked", oracle="VULNERABLE"),
        case("PHP-FPM port exposed directly", f"{REG}php:8.5.11-fpm", "FPM_EXPOSED", oracle=None, cport=9000),
        case(f"Ubuntu {UBU_OLD} warnings shown", f"p2s-lab/ubuntu-php:{UBU_OLD}", "ORACLE_VULNERABLE", ini=SHOW,
             ini_path=UBU_INI, oracle="VULNERABLE", build=("Dockerfile.ubuntu", {"PHPPKG": UBU_OLD})),
        case(f"Ubuntu {UBU_NEW} backport, warnings shown", f"p2s-lab/ubuntu-php:{UBU_NEW}", "ORACLE_PATCHED", ini=SHOW,
             ini_path=UBU_INI, oracle="PATCHED", build=("Dockerfile.ubuntu", {"PHPPKG": UBU_NEW})),
        # nothing disclosed: default discovery still proves PHP via /index.php (2.8 and --no-deep: NO_PHP_INDICATOR, a miss)
        case(f"Ubuntu {UBU_OLD} production php.ini", f"p2s-lab/ubuntu-php:{UBU_OLD}", "PHP_VERSION_HIDDEN",
             ini_path=UBU_INI, oracle="SILENT", build=("Dockerfile.ubuntu", {"PHPPKG": UBU_OLD})),
    ]
    if full:
        for v in ("8.5.11", "8.5.12"):
            out.append(case(f"{v} phpredis session handler", f"p2s-lab/php-redis:{v}", "LIKELY_VULNERABLE" if v == "8.5.11"
                            else "PATCHED_BY_BANNER", oracle="SILENT", build=("Dockerfile.redis", {"BASE": off(v)}), needs="redis"))
    return out


def sh(*a, check=True):
    return subprocess.run(a, capture_output=True, text=True, check=check)


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  ({detail})" if detail else ""), flush=True)
    if not cond:
        FAIL.append(name)


def ensure_image(c):
    if not c["build"] or sh("docker", "image", "inspect", c["image"], check=False).returncode == 0:
        return
    df, args = c["build"]
    if "BASE" not in args and REG:
        args = dict(args, BASE=f"{REG}ubuntu:24.04")
    cmd = ["docker", "build", "-q", "-f", os.path.join(HERE, "oracle_lab", df), "-t", c["image"]]
    for k, v in args.items():
        cmd += ["--build-arg", f"{k}={v}"]
    print(f"[*] building {c['image']}", flush=True)
    subprocess.run(cmd + [os.path.join(HERE, "oracle_lab")], check=True, stdout=subprocess.DEVNULL)


def wait_http(port, deadline, raw=False):
    while time.monotonic() < deadline:
        try:
            if raw:  # FastCGI: a TCP accept is all we can wait for
                socket.create_connection(("127.0.0.1", port), 2).close()
                return True
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)  # noqa: S310 - local lab container
            return True
        except urllib.error.HTTPError:
            return True  # 403/404 still means the server is up
        except Exception:
            time.sleep(0.5)
    return False


def scan_one(port, out):
    subprocess.run([sys.executable, os.path.join(ROOT, "php2shell_scan.py"), "-t", "127.0.0.1", "--ports", str(port), "--scope",
                    "127.0.0.1", "--authorized", "--oracle", "-o", out, "--formats", "json"], capture_output=True, timeout=120)
    return json.loads(open(os.path.join(out, "results.jsonl")).readline())["status"]


def restart_scenario(net, work, port, started):
    """In-place upgrade to the backport without a restart: the oracle sees the code the workers still run."""
    c = case("restart", f"p2s-lab/ubuntu-php:{UBU_OLD}", "", build=("Dockerfile.ubuntu", {"PHPPKG": UBU_OLD}))
    ensure_image(c)
    ini, name = os.path.join(work, "restart.ini"), f"{net}-restart"
    open(ini, "w").write(SHOW)
    sh("docker", "run", "-d", "--rm", "--name", name, "-p", f"127.0.0.1:{port}:80", "-v", f"{os.path.join(work, 'plain')}:/var/www/html:ro",
       "-v", f"{ini}:{UBU_INI}:ro", c["image"])
    started.append(name)
    wait_http(port, time.monotonic() + 60)
    pk = " ".join(f"{p}={UBU_NEW}" for p in ("php8.3-common", "php8.3-cli", "php8.3-opcache", "php8.3-readline", "libapache2-mod-php8.3"))
    sh("docker", "exec", name, "sh", "-c", f"apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {pk}")
    check("restart: upgraded on disk, not restarted -> ORACLE_VULNERABLE", scan_one(port, os.path.join(work, "r1")) == "ORACLE_VULNERABLE")
    sh("docker", "exec", name, "apache2ctl", "-k", "graceful", check=False)
    time.sleep(3)
    check("restart: after apache2ctl graceful still -> ORACLE_VULNERABLE", scan_one(port, os.path.join(work, "r2")) == "ORACLE_VULNERABLE")
    sh("docker", "restart", "-t", "1", name)
    wait_http(port, time.monotonic() + 60)
    check("restart: after stop/start -> ORACLE_PATCHED", scan_one(port, os.path.join(work, "r3")) == "ORACLE_PATCHED")


def main():
    if not shutil.which("docker") or sh("docker", "info", check=False).returncode:
        print("SKIP: docker not available")
        return 0
    full = "--full" in sys.argv
    work = tempfile.mkdtemp(prefix="p2s-oracle-lab-")
    net, started = f"p2s-lab-{os.getpid()}", []
    all_cases = cases(full)
    try:
        sh("docker", "network", "create", net)
        for c in all_cases:
            ensure_image(c)
        if any(c["needs"] == "redis" for c in all_cases):
            sh("docker", "run", "-d", "--rm", "--name", f"{net}-redis", "--network", net, "--network-alias", "redis", f"{REG}redis:7-alpine")
            started.append(f"{net}-redis")
        for name, files in DOCROOTS.items():
            for fn, body in files.items():
                os.makedirs(os.path.dirname(os.path.join(work, name, fn)), exist_ok=True)
                open(os.path.join(work, name, fn), "w").write(body)
        for i, c in enumerate(all_cases):
            port, cname = BASE_PORT + i, f"{net}-{i}"
            ini = os.path.join(work, f"{i}.ini")
            open(ini, "w").write(c["ini"])
            vols = ["-v", f"{os.path.join(work, c['doc'])}:/var/www/html:ro", "-v", f"{ini}:{c['ini_path']}:ro"]
            if c["fpm"]:
                conf = os.path.join(work, f"{i}.nginx.conf")
                open(conf, "w").write("server { listen 80; root /var/www/html; index index.php;\n"
                                      f"  location ~ \\.php$ {{ fastcgi_pass {cname}-fpm:9000; include fastcgi_params;\n"
                                      "    fastcgi_param SCRIPT_FILENAME /var/www/html$fastcgi_script_name; } }\n")
                sh("docker", "run", "-d", "--rm", "--name", f"{cname}-fpm", "--network", net, *vols, c["image"])
                started.append(f"{cname}-fpm")
                sh("docker", "run", "-d", "--rm", "--name", cname, "--network", net, "-p", f"127.0.0.1:{port}:80",
                   "-v", f"{os.path.join(work, c['doc'])}:/var/www/html:ro", "-v", f"{conf}:/etc/nginx/conf.d/default.conf:ro",
                   f"{REG}nginx:1.27-alpine")
            else:
                sh("docker", "run", "-d", "--rm", "--name", cname, "--network", net, "-p", f"127.0.0.1:{port}:{c['cport']}", *vols, c["image"])
            started.append(cname)
        deadline = time.monotonic() + 60
        for i, c in enumerate(all_cases):
            if not wait_http(BASE_PORT + i, deadline, raw=c["cport"] != 80):
                check(f"{c['name']}: container answers HTTP", False)

        out = os.path.join(work, "out")
        ports = ",".join(str(BASE_PORT + i) for i in range(len(all_cases)))
        p = subprocess.run([sys.executable, os.path.join(ROOT, "php2shell_scan.py"), "-t", "127.0.0.1", "--ports", ports,
                            "--scope", "127.0.0.1", "--authorized", "--oracle", "-o", out, "--formats", "json,html"],
                           capture_output=True, text=True, timeout=600)
        res = {r["port"]: r for r in (json.loads(x) for x in open(os.path.join(out, "results.jsonl")))}
        for i, c in enumerate(all_cases):
            r = res.get(BASE_PORT + i, {})
            o = r.get("oracle") or {}
            check(f"{c['name']} -> {c['expect']} (oracle {c['oracle']})",
                  r.get("status") == c["expect"] and o.get("result") == c["oracle"],
                  f"got {r.get('status')} / oracle {o.get('result')} {o.get('markers')}/3 {o.get('path')}")
        check("scan exit code: actionable", p.returncode == 2, f"rc={p.returncode} {p.stderr[-300:]}")
        html = open(os.path.join(out, "report.html"), encoding="utf-8").read()
        check("report method section declares the active check", "--oracle" in html, "")
        if full:
            restart_scenario(net, work, BASE_PORT + len(all_cases), started)
    finally:
        for n in reversed(started):
            sh("docker", "stop", "-t", "1", n, check=False)
        for _ in range(20):  # --rm removal is asynchronous; the network is busy until it finishes
            if sh("docker", "network", "rm", net, check=False).returncode == 0 or \
                    sh("docker", "network", "inspect", net, check=False).returncode:
                break
            time.sleep(0.5)
        shutil.rmtree(work, ignore_errors=True)
    print("\n" + ("ALL PASSED" if not FAIL else f"{len(FAIL)} FAILED: {FAIL}"))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
