"""Comparative benchmark: php2shell-scanner vs public PHP2Shell scanners on targets with known ground truth.

Isolation: targets and tools share one `--internal` Docker network (no route to the internet or the host LAN); the
tools are third-party code, read before use, mounted read-only and run in a throw-away python:3.12-slim container.
Only scanners run: exploit / crash-oriented repos are excluded (see docs/BENCHMARK.md for the reasoning per repo).

  BENCH_TOOLS=<dir with the cloned repos> python3 tests/benchmark.py [--out results.json]

Every tool's raw output is normalised to VULN (says vulnerable) / PATCHED / UNKNOWN (PHP seen, no verdict, or "verify")
/ NONE (no PHP signal). Scoring against the truth: a vulnerable target reported PATCHED or NONE is a MISS (the dangerous
error), a patched target reported VULN is a FALSE ALARM.
"""
import json, os, re, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
NET = "p2s-bench"
SUBNET = os.environ.get("BENCH_SUBNET", "10.250.250.0/24")  # a /24 no other Docker network uses
PREFIX = SUBNET.rsplit(".", 1)[0] + "."
PY = os.environ.get("BENCH_PYTHON_IMAGE", "public.ecr.aws/docker/library/python:3.12-slim")
NUCLEI = os.environ.get("BENCH_NUCLEI_IMAGE", "projectdiscovery/nuclei:v3.4.10")
UBU_OLD, UBU_NEW = "p2s-lab/ubuntu-php:8.3.6-0maysync1", "p2s-lab/ubuntu-php:8.3.6-0ubuntu0.24.04.13"
UBU_INI, OFF_INI = "/etc/php/8.3/apache2/conf.d/99-bench.ini", "/usr/local/etc/php/conf.d/99-bench.ini"
SHOW = "display_errors=1\ndisplay_startup_errors=1\n"

# name, image, truth (V vulnerable / P patched / N no PHP), ini, ini path, docroot, container port, what it models
TARGETS = [
    ("up-8.5.11", "php:8.5.11-apache", "V", "", OFF_INI, "plain", 80, "upstream pre-fix, banner + warnings shown (container default)"),
    ("up-8.5.12", "php:8.5.12-apache", "P", "", OFF_INI, "plain", 80, "upstream fixed, banner + warnings shown"),
    ("up-8.5.11-quiet", "php:8.5.11-apache", "V", "display_errors=0\n", OFF_INI, "plain", 80, "pre-fix, banner shown, warnings hidden"),
    ("up-8.5.11-hidden", "php:8.5.11-apache", "V", "display_errors=0\nexpose_php=0\n", OFF_INI, "plain", 80, "pre-fix, nothing disclosed"),
    ("ubuntu-old-prod", UBU_OLD, "V", "", UBU_INI, "plain", 80, "Ubuntu 24.04 pre-fix package, distro production php.ini"),
    ("ubuntu-new-prod", UBU_NEW, "P", "", UBU_INI, "plain", 80, "Ubuntu 24.04 backport, distro production php.ini"),
    ("ubuntu-old-banner", UBU_OLD, "V", "expose_php=1\n", UBU_INI, "plain", 80, "Ubuntu pre-fix, banner PHP/8.3.6"),
    ("ubuntu-new-banner", UBU_NEW, "P", "expose_php=1\n", UBU_INI, "plain", 80, "Ubuntu backport, SAME banner PHP/8.3.6"),
    ("ubuntu-old-show", UBU_OLD, "V", "expose_php=1\n" + SHOW, UBU_INI, "plain", 80, "Ubuntu pre-fix, banner + warnings shown"),
    ("ubuntu-new-show", UBU_NEW, "P", "expose_php=1\n" + SHOW, UBU_INI, "plain", 80, "Ubuntu backport, banner + warnings shown"),
    ("eol-7.4-show", "php:7.4-apache", "V", SHOW, OFF_INI, "plain", 80, "EOL 7.4, warnings shown"),
    ("static-front", "php:8.5.11-apache", "V", "", OFF_INI, "linked", 80, "pre-fix PHP behind a link on a static front page"),
    ("no-php", "php:8.5.11-apache", "N", "", OFF_INI, "static", 80, "static site, no PHP executed"),
    ("fpm-9000", "php:8.5.11-fpm", "V", "", OFF_INI, "plain", 9000, "PHP-FPM socket exposed on 9000, pre-fix"),
]
DOCROOTS = {"plain": {"index.php": "<?php echo 'bench';\n"},
            "linked": {"index.html": '<html><a href="portal/search.php">search</a></html>\n', "portal/search.php": "<?php echo 'r';\n"},
            "static": {"index.html": "<html>static</html>\n"}}


def sh(*a, check=True, timeout=None, **kw):
    return subprocess.run(a, capture_output=True, text=True, check=check, timeout=timeout, **kw)


def ex(cmd, timeout=300):
    p = subprocess.run(["docker", "exec", "bench-runner", "sh", "-c", cmd], capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


# ----------------------------------------------------------------------------- tools: (name, kind, runner -> (verdict, raw))
VULN_WORDS = ("VULNERABLE",)


def run_ours(t, ip, extra, label):
    out = f"/work/ours-{label}-{t[0]}"
    target = ip if t[6] == 9000 else f"http://{ip}:{t[6]}/"
    rc, raw = ex(f"python3 /p2s/php2shell_scan.py -t {target} --ports {t[6]} --scope {SUBNET} --authorized -o {out} --formats json {extra}")
    try:
        st = json.load(open(WORK + out[5:] + "/assets.json"))["assets"][0]["final_status"]
    except (OSError, IndexError, KeyError, ValueError):
        return "NONE", raw[-300:]
    m = {"FPM_EXPOSED": "VULN", "VERIFIED_VULNERABLE": "VULN", "ORACLE_VULNERABLE": "VULN", "LIKELY_VULNERABLE": "VULN",
         "EOL_NO_UPSTREAM_FIX": "VULN", "VERIFIED_RESTART_REQUIRED": "VULN", "VERIFY_DISTRO_BACKPORT": "UNKNOWN",
         "PHP_VERSION_HIDDEN": "UNKNOWN", "PATCHED_BY_BANNER": "PATCHED", "ORACLE_PATCHED": "PATCHED", "VERIFIED_PATCHED": "PATCHED"}
    return m.get(st, "NONE"), st


def run_zarguell(t, ip):
    rc, raw = ex(f"cd /tools/zarguell_php2shell-scanner && timeout 240 python3 php2shell_scanner.py {ip} -p {t[6]} --json", 300)
    vs = re.findall(r'"verdict"\s*:\s*"([A-Z_]+)"', raw)
    if any(v in ("VULNERABLE", "LIKELY_VULNERABLE") for v in vs):
        return "VULN", ",".join(vs)
    if "PATCHED" in vs:
        return "PATCHED", ",".join(vs)
    if any(v in ("PHP_NO_VERSION", "PHP_CANNOT_RULE_OUT", "PHP_UNKNOWN") for v in vs):
        return "UNKNOWN", ",".join(vs)
    return "NONE", ",".join(vs) or raw[-200:]


def _verdict_line(raw):
    return next((ln.strip() for ln in reversed(re.sub(r"\x1b\[[0-9;]*m", "", raw).splitlines())
                 if re.search(r"LIKELY VULNERABLE|LIKELY PATCHED|UNDETERMINED|AFFECTED|CONFIRMED", ln)), "")


def run_simple(repo, script):
    def run(t, ip):
        rc, raw = ex(f"cd /tools/{repo} && timeout 120 python3 {script} --target http://{ip}:{t[6]} --yes", 150)
        line = _verdict_line(raw)
        if re.search(r"LIKELY VULNERABLE|AFFECTED|CONFIRMED", line):
            return "VULN", line
        if "LIKELY PATCHED" in line:
            return "PATCHED", line
        if "PHP present" in line or "version hidden" in line:
            return "UNKNOWN", line
        return "NONE", line or raw[-200:]
    return run


def run_bladehstream(t, ip):
    port = f"--port {t[6]}" if t[6] != 9000 else "--port 80 --fpm-port 9000"
    rc, raw = ex(f"cd /tools/bladehstream_php2shell_detect && timeout 120 python3 php_cve_scanner.py --target {ip} {port} "
                 f"--output /work/blade-{t[0]}.json", 150)
    try:
        doc = json.load(open(f"{WORK}/blade-{t[0]}.json"))
    except (OSError, ValueError):
        return "NONE", raw[-200:]
    fs = doc if isinstance(doc, list) else doc.get("findings", [])
    if any(f.get("vulnerable") is True for f in fs):
        return "VULN", "vulnerable=True"
    if any(f.get("vulnerable") is False for f in fs):
        return "PATCHED", "vulnerable=False"
    return ("UNKNOWN", "vulnerable=None") if fs else ("NONE", "no finding")


def run_joas(t, ip):
    rc, raw = ex(f"cd /tools/JoasASantos_php2shell-scanner && timeout 120 python3 php2shell_scan.py http://{ip}:{t[6]}/ "
                 f"-o /work/joas-{t[0]}.json", 150)
    try:
        doc = json.load(open(f"{WORK}/joas-{t[0]}.json"))
    except (OSError, ValueError):
        return "NONE", raw[-200:]
    text = json.dumps(doc)
    sts = re.findall(r'"status"\s*:\s*"([A-Z_]+)"', text)
    if any(s.startswith("VULNERABLE") for s in sts):
        return "VULN", ",".join(sts)
    if "PATCHED" in sts:
        return "PATCHED", ",".join(sts)
    if re.search(r'"php_detected"\s*:\s*true|"php"\s*:\s*true', text) or "UNKNOWN" in sts:
        return "UNKNOWN", ",".join(sts)
    return "NONE", ",".join(sts)


def run_nuclei(templates, label):
    def run(t, ip):
        url = f"http://{ip}:{t[6]}/"
        out = f"/work/nuclei-{label}-{t[0]}.jsonl"
        tf = " ".join(f"-t /tpl/{x}" for x in templates)
        p = subprocess.run(["docker", "run", "--rm", "--network", NET, "-v", f"{WORK}:/work", "-v", f"{TPL}:/tpl:ro", NUCLEI,
                            "-u", url, *sum((["-t", f"/tpl/{x}"] for x in templates), []), "-duc", "-ni", "-silent", "-jsonl",
                            "-o", out, "-timeout", "60"], capture_output=True, text=True, timeout=600)
        try:
            hits = [json.loads(ln) for ln in open(WORK + out[5:]) if ln.strip()]
        except OSError:
            hits = []
        if hits:
            return "VULN", ",".join(sorted({h.get("template-id", "") for h in hits}))
        return "NONE", (p.stderr or "")[-160:].replace("\n", " ") or "no match"
    return run


TOOLS = [
    ("php2shell-scanner --no-deep (passive)", "ours", lambda t, ip: run_ours(t, ip, "--no-deep", "passive")),
    ("php2shell-scanner (default)", "ours", lambda t, ip: run_ours(t, ip, "", "default")),
    ("php2shell-scanner --oracle", "ours", lambda t, ip: run_ours(t, ip, "--oracle", "oracle")),
    ("zarguell/php2shell-scanner", "zarguell_php2shell-scanner", run_zarguell),
    ("CyberRoute/php2shell-scanner", "CyberRoute_php2shell-scanner", run_simple("CyberRoute_php2shell-scanner", "scan.py")),
    ("mohamedation/php2shell-scanner", "mohamedation_php2shell-scanner", run_simple("mohamedation_php2shell-scanner", "scan.py")),
    ("bladehstream/php2shell_detect", "bladehstream_php2shell_detect", run_bladehstream),
    ("JoasASantos/php2shell-scanner", "JoasASantos_php2shell-scanner", run_joas),
    ("nuclei: Ademking CVE-2026-109618/9", "Ademking_php2shell-nuclei-templates",
     run_nuclei(["ademking/CVE-2026-109618.yaml", "ademking/CVE-2026-109619.yaml"], "ademking")),
    ("nuclei: ProjectDiscovery CVE-2026-109618 (intrusive)", "pd", run_nuclei(["pd/CVE-2026-109618.yaml"], "pd")),
]


def score(truth, v):
    if truth == "V":
        return {"VULN": "HIT", "UNKNOWN": "VERIFY", "PATCHED": "MISS", "NONE": "MISS"}[v]
    if truth == "P":
        return {"VULN": "FALSE_ALARM", "UNKNOWN": "VERIFY", "PATCHED": "OK", "NONE": "OK_NO_PHP"}[v]
    return {"VULN": "FALSE_ALARM", "UNKNOWN": "VERIFY", "PATCHED": "OK", "NONE": "OK"}[v]


def main():
    global WORK, TPL
    tools_dir = os.environ.get("BENCH_TOOLS")
    if not tools_dir or not shutil.which("docker"):
        print("SKIP: set BENCH_TOOLS to the directory with the cloned tools (and have docker)")
        return 0
    out_path = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else os.path.join(os.getcwd(), "benchmark-results.json")
    WORK = tempfile.mkdtemp(prefix="p2s-bench-", dir=os.environ.get("BENCH_WORKDIR"))
    TPL = os.path.join(WORK, "tpl")
    os.makedirs(os.path.join(TPL, "ademking"))
    os.makedirs(os.path.join(TPL, "pd"))
    for x in ("CVE-2026-109618.yaml", "CVE-2026-109619.yaml"):
        shutil.copy(os.path.join(tools_dir, "Ademking_php2shell-nuclei-templates", "templates", "php2shell", x), os.path.join(TPL, "ademking", x))
    shutil.copy(os.path.join(tools_dir, "pd-CVE-2026-109618.yaml"), os.path.join(TPL, "pd", "CVE-2026-109618.yaml"))
    started = []
    try:
        sh("docker", "network", "create", "--internal", "--subnet", SUBNET, NET)
        for name, files in DOCROOTS.items():
            for fn, body in files.items():
                os.makedirs(os.path.dirname(os.path.join(WORK, "doc", name, fn)), exist_ok=True)
                open(os.path.join(WORK, "doc", name, fn), "w").write(body)
        ips = {}
        for i, (name, image, truth, ini, ini_path, doc, cport, _) in enumerate(TARGETS):
            ip = f"{PREFIX}{10 + i}"
            f = os.path.join(WORK, f"{name}.ini")
            open(f, "w").write(ini)
            sh("docker", "run", "-d", "--rm", "--name", f"bench-{name}", "--network", NET, "--ip", ip,
               "-v", f"{WORK}/doc/{doc}:/var/www/html:ro", "-v", f"{f}:{ini_path}:ro", image)
            started.append(f"bench-{name}")
            ips[name] = ip
        sh("docker", "run", "-d", "--rm", "--name", "bench-runner", "--network", NET, "--ip", f"{PREFIX}2",
           "-v", f"{tools_dir}:/tools:ro", "-v", f"{ROOT}:/p2s:ro", "-v", f"{WORK}:/work", PY, "sleep", "infinity")
        started.append("bench-runner")
        time.sleep(6)
        rc, raw = ex("python3 -c \"import urllib.request; urllib.request.urlopen('https://pypi.org', timeout=5)\"", 30)
        isolated = rc != 0
        print(f"[*] isolation check (runner -> internet): {'blocked' if isolated else 'REACHABLE'}", flush=True)
        if not isolated:
            raise SystemExit("[x] the benchmark network reaches the internet: refusing to run third-party code")
        results = []
        for tool, repo, fn in TOOLS:
            if repo not in ("ours", "pd") and not os.path.isdir(os.path.join(tools_dir, repo)):
                print(f"SKIP {tool}: {repo} not in BENCH_TOOLS")
                continue
            for t in TARGETS:
                t0 = time.monotonic()
                try:
                    v, detail = fn(t, ips[t[0]])
                except subprocess.TimeoutExpired:
                    v, detail = "NONE", "timeout"
                results.append({"tool": tool, "target": t[0], "truth": t[2], "verdict": v, "score": score(t[2], v),
                                "detail": str(detail)[:200], "seconds": round(time.monotonic() - t0, 1)})
                print(f"{tool[:42]:42} {t[0]:18} truth={t[2]} -> {v:8} {score(t[2], v):12} {str(detail)[:70]}", flush=True)
        json.dump({"targets": [dict(zip(("name", "image", "truth", "ini", "ini_path", "doc", "port", "models"), t)) for t in TARGETS],
                   "results": results}, open(out_path, "w"), indent=1)
        print(f"[*] results: {out_path}")
    finally:
        for c in reversed(started):
            sh("docker", "stop", "-t", "1", c, check=False)
        for _ in range(20):
            if sh("docker", "network", "rm", NET, check=False).returncode == 0:
                break
            time.sleep(0.5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
