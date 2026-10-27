"""End-to-end checks against local mock servers. Run: python3 tests/integration_test.py"""
import asyncio, os, signal, ssl, subprocess, sys, tempfile, threading, time, json, http.server
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from p2s import engine as E  # noqa: E402

FAIL = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  ({detail})" if detail else ""))
    if not cond:
        FAIL.append(name)


def cli(*args, timeout=120, sig_after=None):
    p = subprocess.Popen([sys.executable, os.path.join(ROOT, "php2shell_scan.py"), *args],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if sig_after:
        time.sleep(sig_after)
        p.send_signal(signal.SIGINT)
    out, _ = p.communicate(timeout=timeout)
    return p.returncode, out


def legacy_tls_server(port, cert, key):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        def do_GET(s):
            s.send_response(200); s.send_header("X-Powered-By", "PHP/5.6.40"); s.end_headers(); s.wfile.write(b"ok")
        def log_message(*a): pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def main():
    mock = subprocess.Popen([sys.executable, os.path.join(HERE, "mock_servers.py"), "a", "120"], stdout=subprocess.PIPE, text=True)
    mock.stdout.readline()
    tmp = tempfile.mkdtemp()
    try:
        # 1. every connection (tcp, http, deep paths) goes through the global limiter
        class Counting(E.RateLimiter):
            calls = 0
            async def wait(self):
                Counting.calls += 1
                await super().wait()
        orig = E.RateLimiter
        E.RateLimiter = Counting
        eps, _ = E.parse_targets(["127.0.0.1"], [8101, 8102, 8103, 8106], 10)
        st = E.Store(os.path.join(tmp, "rl.jsonl"), False)
        opts = {"concurrency": 50, "per_host": 4, "rate": 10, "connect_timeout": 2, "http_timeout": 3,
                "tls_timeout": 2, "deep": True, "retries": 1}
        t0 = time.monotonic()
        asyncio.run(E.run_scan(eps, opts, st, quiet=True))
        el = time.monotonic() - t0
        st.close()
        E.RateLimiter = orig
        per_ep = 1 + 1 + 1 + len(E.DEEP_PATHS)  # tcp + GET + --deep: random .php baseline + probe paths (mock pages link no .php)
        check("rate limit covers tcp+http+deep connections", Counting.calls == 4 * per_ep, f"{Counting.calls} limiter calls, expected {4 * per_ep}")
        check(f"rate 10/s respected for {4 * per_ep} connections", el >= (4 * per_ep - 2) / 10, f"{el:.2f}s")

        # 2. TLS 1.0-only host (typical for EOL PHP) is reachable
        cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "2",
                        "-subj", "/CN=legacy.test"], capture_output=True, check=True)
        try:
            legacy_tls_server(8444, cert, key)
            started = True
        except (ssl.SSLError, ValueError, OSError) as e:
            started = False
            print(f"SKIP legacy TLS server could not start here: {e}")
        if started:
            rc, out = cli("-t", "https://127.0.0.1:8444/", "--scope", "127.0.0.1", "--authorized", "-o", os.path.join(tmp, "tls"), "--formats", "json")
            r = E.load_results(os.path.join(tmp, "tls", "results.jsonl"))[0]
            check("TLS 1.0-only host scanned", r["status"] == "EOL_NO_UPSTREAM_FIX", f"{r['status']} {r.get('note', '')[:80]}")

        # 3. scope is fail-closed: one out-of-scope host aborts the whole run before any traffic
        out_dir = os.path.join(tmp, "scope_bad")
        rc, out = cli("-t", "127.0.0.1", "127.0.0.9", "--ports", "8101", "--scope", "127.0.0.0/30", "--authorized", "-o", out_dir)
        check("out-of-scope target aborts run", rc == 1 and "127.0.0.9" in out and not os.path.exists(os.path.join(out_dir, "results.jsonl")),
              f"rc={rc}")
        rc, out = cli("-t", "127.0.0.1", "--ports", "8101", "--scope", "127.0.0.0/30", "--authorized", "-o",
                      os.path.join(tmp, "scope_ok"), "--formats", "json")
        meta = json.load(open(os.path.join(tmp, "scope_ok", "meta.json")))
        check("in-scope run completes, actionable exit code", rc == 2 and meta["complete"] is True and meta["scope_check"].startswith("enforced"),
              f"rc={rc} meta={meta.get('scope_check')}")

        # 4. interrupted scan is flagged as incomplete in exit code, meta and reports
        out_dir = os.path.join(tmp, "partial")
        rc, out = cli("-t", "10.255.255.0/24", "--ports", "81,82", "--no-scope", "--authorized", "-o", out_dir, "--rate", "20",
                      "--connect-timeout", "2", "--formats", "html,json", sig_after=3)
        meta = json.load(open(os.path.join(out_dir, "meta.json")))
        html = open(os.path.join(out_dir, "report.html")).read()
        check("interrupted scan -> exit 3 + meta.complete False + banner",
              rc == 3 and meta["complete"] is False and meta["missing"] > 0 and "INCOMPLETE SCAN" in html, f"rc={rc} missing={meta.get('missing')}")
        # resume finishes the remaining endpoints (2 ports x 254 hosts) - shortened via tiny timeouts
        rc, out = cli("-t", "10.255.255.0/24", "--ports", "81,82", "--no-scope", "--authorized", "-o", out_dir, "--resume", "--rate", "0",
                      "--connect-timeout", "0.3", "--retries", "0", "--formats", "json", timeout=300)
        meta = json.load(open(os.path.join(out_dir, "meta.json")))
        n = len(E.load_results(os.path.join(out_dir, "results.jsonl")))
        check("resume completes the partial scan", meta["complete"] is True and n == 508 and rc == 0, f"rc={rc} results={n}")
        # 5. redirect to a non-HTTP port keeps the first hop's banner; redirects never leave the scanned port set
        for ports, label in (("8110,8109", "followed, hop fails"), ("8110", "not followed: port outside scan")):
            d = os.path.join(tmp, "redir" + ports.replace(",", "_"))
            rc, out = cli("-t", "127.0.0.1", "--ports", ports, "--scope", "127.0.0.1", "--authorized", "-o", d, "--formats", "json")
            r = {x["port"]: x for x in E.load_results(os.path.join(d, "results.jsonl"))}[8110]
            check(f"redirect {label}: banner kept", r["status"] == "EOL_NO_UPSTREAM_FIX" and rc == 2, f"{r['status']} | {r.get('note', '')[:90]}")
        # 6. a fresh scan into an existing folder does not inherit old host verdicts
        d = os.path.join(tmp, "scope_ok")
        json.dump({"127.0.0.1": {"verdict": "PATCHED", "summary": "stale", "versions": []}}, open(os.path.join(d, "verify.json"), "w"))
        rc, out = cli("-t", "127.0.0.1", "--ports", "8101", "--scope", "127.0.0.0/30", "--authorized", "-o", d, "--formats", "json")
        a = json.load(open(os.path.join(d, "assets.json")))["assets"][0]
        check("stale verify.json not reused by a fresh scan", a["final_status"] == "LIKELY_VULNERABLE" and os.path.exists(os.path.join(d, "verify.json.prev")),
              a["final_status"])
        # 7. scope is required unless explicitly waived; verification needs --authorized and stays in scope
        rc, out = cli("-t", "127.0.0.1", "--ports", "8101", "--authorized", "-o", os.path.join(tmp, "noscope"))
        check("scan without --scope/--no-scope refused (usage error = exit 1)", rc == 1 and "scope is required" in out, f"rc={rc}")
        smap = os.path.join(tmp, "ssh_map.txt")
        open(smap, "w").write("127.0.0.1 root@10.9.9.9\n")
        rc, out = cli("--report-only", "-o", d, "--verify-all", "--ssh-map", smap, "--scope", "127.0.0.0/30", "--authorized")
        check("ssh target outside scope refused before connecting", rc == 1 and "10.9.9.9" in out, f"rc={rc}")
        # 8. ssh-map keyed by the DNS NAME maps onto the pinned-IP asset; dual-stack ::1 is dropped as a gap, not an abort
        d = os.path.join(tmp, "byname")
        open(smap, "w").write("localhost nobody@127.0.0.1 port=1\n")  # port 1: refused fast, we only check the mapping
        rc, out = cli("-t", "localhost", "--ports", "8101", "--scope", "127.0.0.1", "localhost", "--authorized", "-o", d,
                      "--verify", "--ssh-map", smap, "--ssh-known-hosts", os.path.join(tmp, "kh"), "--formats", "json")
        v = json.load(open(os.path.join(d, "verify.json")))
        check("ssh-map by hostname verifies the pinned IP asset", "SSH verification: 1 host" in out and list(v) == ["127.0.0.1"],
              f"rc={rc} keys={list(v)}")
        # 9. a bad ssh-map is refused BEFORE scanning (no traffic, nothing half-written)
        d = os.path.join(tmp, "badmap")
        open(smap, "w").write("127.0.0.1 root@10.9.9.9\n")
        rc, out = cli("-t", "127.0.0.1", "--ports", "8101", "--scope", "127.0.0.1", "--authorized", "-o", d,
                      "--verify", "--ssh-map", smap)
        check("ssh scope violation refused before the scan", rc == 1 and not os.path.exists(os.path.join(d, "results.jsonl")), f"rc={rc}")
        # 10. a dry run leaves nothing on disk; conflicting scope flags are a usage error
        d = os.path.join(tmp, "dry")
        rc, out = cli("-t", "localhost", "--ports", "8101", "--scope", "127.0.0.1", "localhost", "-o", d, "--list")
        check("--list writes nothing", rc == 0 and not os.path.exists(d), f"rc={rc} exists={os.path.exists(d)}")
        rc, out = cli("-t", "127.0.0.1", "--scope", "127.0.0.1", "--no-scope", "--authorized", "-o", os.path.join(tmp, "x"))
        check("--scope with --no-scope rejected", rc == 1 and "cannot be used together" in out, f"rc={rc}")
        # 11. --oracle: POSTs go through the limiter (decisive answer stops early), statuses move, default stays GET-only
        Counting.calls = 0
        E.RateLimiter = Counting
        eps, _ = E.parse_targets(["127.0.0.1"], [8111, 8101], 10)
        st = E.Store(os.path.join(tmp, "or.jsonl"), False)
        asyncio.run(E.run_scan(eps, dict(opts, rate=0, oracle=True), st, quiet=True))
        st.close()
        E.RateLimiter = orig
        check("oracle POSTs are rate limited: 1 on a decisive answer, 2 when silent", Counting.calls == 2 * per_ep + 1 + 2,
              f"{Counting.calls} limiter calls, expected {2 * per_ep + 3}")
        d = os.path.join(tmp, "oracle")
        rc, out = cli("-t", "127.0.0.1", "--ports", "8111,8112,8101", "--scope", "127.0.0.1", "--authorized", "--oracle", "-o", d,
                      "--formats", "json,html")
        r = {x["port"]: x for x in E.load_results(os.path.join(d, "results.jsonl"))}
        got = {p: (r[p]["status"], r[p]["oracle"]["result"]) for p in r}
        check("oracle: hidden pre-fix -> ORACLE_VULNERABLE, Ubuntu backport -> ORACLE_PATCHED, silent keeps banner",
              got == {8111: ("ORACLE_VULNERABLE", "VULNERABLE"), 8112: ("ORACLE_PATCHED", "PATCHED"), 8101: ("LIKELY_VULNERABLE", "SILENT")},
              str(got))
        meta = json.load(open(os.path.join(d, "meta.json")))
        check("oracle run recorded in meta and report", meta.get("oracle") is True and "--oracle" in open(os.path.join(d, "report.html")).read(),
              str(meta.get("oracle")))
        rc, out = cli("--report-only", "-o", d, "--scope", "127.0.0.1", "--formats", "json")
        check("--report-only keeps the oracle flag", json.load(open(os.path.join(d, "meta.json"))).get("oracle") is True, "")
        d = os.path.join(tmp, "no_oracle")
        rc, out = cli("-t", "127.0.0.1", "--ports", "8111", "--scope", "127.0.0.1", "--authorized", "-o", d, "--formats", "json")
        r = E.load_results(os.path.join(d, "results.jsonl"))[0]
        check("without --oracle no POST is sent (status from banner only)", r["status"] == "PHP_VERSION_HIDDEN" and "oracle" not in r,
              r["status"])
        # 12. --deep discovery: catch-all SPA stays clean, header-less WordPress is found by content, PHP behind a link
        d = os.path.join(tmp, "deep")
        rc, out = cli("-t", "127.0.0.1", "--ports", "8113,8114,8115", "--scope", "127.0.0.1", "--authorized", "--deep", "--oracle",
                      "-o", d, "--formats", "json")
        r = {x["port"]: x for x in E.load_results(os.path.join(d, "results.jsonl"))}
        check("catch-all SPA: 200 on every .php is not PHP evidence", r[8113]["status"] == "NO_PHP_INDICATOR" and r[8113].get("catch_all"),
              f"{r[8113]['status']} {r[8113]['indicators']}")
        check("WordPress with stripped headers found by /wp-login.php content", r[8114]["status"] == "PHP_VERSION_HIDDEN"
              and "app:WordPress" in r[8114]["indicators"], f"{r[8114]['status']} {r[8114]['indicators']}")
        check("static front page: oracle follows the harvested .php link", r[8115]["status"] == "ORACLE_VULNERABLE"
              and r[8115]["oracle"]["path"] == "/portal/search.php", f"{r[8115]['status']} {r[8115].get('oracle')}")
        # 13. exposed FastCGI on a non-HTTP port is found and ranks first; a non-FastCGI raw port stays NO_WEB_RESPONSE
        d = os.path.join(tmp, "fpm")
        rc, out = cli("-t", "127.0.0.1", "--ports", "8116,8109", "--scope", "127.0.0.1", "--authorized", "-o", d, "--formats", "json")
        r = {x["port"]: x for x in E.load_results(os.path.join(d, "results.jsonl"))}
        a = json.load(open(os.path.join(d, "assets.json")))["assets"][0]
        check("exposed PHP-FPM -> FPM_EXPOSED with version, asset status, exit 2",
              r[8116]["status"] == "FPM_EXPOSED" and r[8116]["php_version"] == "8.3.12" and a["final_status"] == "FPM_EXPOSED" and rc == 2,
              f"{r[8116]['status']} {r[8116].get('php_version')} asset={a['final_status']} rc={rc}")
        check("non-FastCGI raw port not mistaken for FPM", r[8109]["status"] == "OPEN_NO_HTTP", r[8109]["status"])
        # 14. --import-local: merged onto the scanned asset by IP; an out-of-scope host's file is refused
        loc = os.path.join(tmp, "local")
        os.makedirs(loc)
        out_ok = "HOST=web1\nBIN=/usr/bin/php8.3|PHP 8.3.12 (cli)\nIP=127.0.0.1\nDONE=1\n"
        json.dump({"format": "php2shell.local/1", "collected_at": "t", "output": out_ok}, open(os.path.join(loc, "web1.json"), "w"))
        json.dump({"format": "php2shell.local/1", "collected_at": "t", "output": out_ok.replace("127.0.0.1", "10.9.9.9")},
                  open(os.path.join(loc, "far.json"), "w"))
        d = os.path.join(tmp, "imported")
        rc, out = cli("-t", "127.0.0.1", "--ports", "8101", "--scope", "127.0.0.1", "--authorized", "--import-local", loc, "-o", d,
                      "--formats", "json")
        a = json.load(open(os.path.join(d, "assets.json")))["assets"]
        # 16. --targets-from nuclei JSONL: scope-checked targets, labels kept, disagreement listed in the report
        nj = os.path.join(tmp, "nuclei.jsonl")
        # nuclei claims 8102 (PHP/8.3.36, patched) is vulnerable; 10.9.9.9 is outside the scope
        open(nj, "w").write(json.dumps({"template-id": "CVE-2026-109618", "host": "http://127.0.0.1:8102", "matched-at": "http://127.0.0.1:8102/"}) + "\n")
        d = os.path.join(tmp, "external")
        rc_x, out_x = cli("--targets-from", nj, "--scope", "127.0.0.1", "--authorized", "-o", d, "--formats", "json,html")
        ax = {x["host"]: x for x in json.load(open(os.path.join(d, "assets.json")))["assets"]}
        html = open(os.path.join(d, "report.html"), encoding="utf-8").read()
        check("--targets-from nuclei: target scanned, external label kept, disagreement reported",
              ax.get("127.0.0.1", {}).get("labels", {}).get("external") == "nuclei:CVE-2026-109618"
              and ax["127.0.0.1"]["final_status"] == "PATCHED_BY_BANNER" and "disagreement with an external tool" in out_x
              and "Disagreements with external tools (1)" in html, f"{ {h: a['final_status'] for h, a in ax.items()} } rc={rc_x}")
        open(nj, "a").write(json.dumps({"template-id": "CVE-2026-109618", "ip": "10.9.9.9", "port": "80"}) + "\n")
        rc_y, out_y = cli("--targets-from", nj, "--scope", "127.0.0.1", "--authorized", "-o", os.path.join(tmp, "external2"))
        check("--targets-from: out-of-scope host from the file aborts before traffic", rc_y == 1 and "10.9.9.9" in out_y, f"rc={rc_y}")
        # 17. MCP: a real scan through the stdio server returns php2shell.findings/1; scope still enforced
        d = os.path.join(tmp, "mcp")
        reqs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "php2shell_scan", "arguments": {
                    "targets": ["127.0.0.1"], "scope": ["127.0.0.1"], "authorized": True, "out_dir": d, "ports": "8101,8116"}}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "php2shell_scan", "arguments": {
                    "targets": ["127.0.0.9"], "scope": ["127.0.0.1"], "authorized": True, "out_dir": d + "2", "ports": "8101"}}}]
        p = subprocess.run([sys.executable, os.path.join(ROOT, "php2shell_scan.py"), "--mcp"], input="\n".join(map(json.dumps, reqs)) + "\n",
                           capture_output=True, text=True, timeout=300)
        resp = {r["id"]: r for r in map(json.loads, p.stdout.splitlines())}
        doc = resp[2]["result"]["structuredContent"]
        check("MCP scan: findings/1 with the FPM and vuln findings; out-of-scope target refused",
              doc.get("format") == "php2shell.findings/1" and sorted(f["kind"] for f in doc["findings"]) == ["fpm", "vuln"]
              and resp[3]["result"]["isError"] and "scope" in resp[3]["result"]["structuredContent"]["error"],
              f"{doc.get('exit_code')} {[f['kind'] for f in doc.get('findings', [])]}")
        # 18. --profile pilot: gentle defaults + evidence pack + nessus; an explicit flag still wins
        d = os.path.join(tmp, "pilot")
        rc_p, out_p = cli("-t", "127.0.0.1", "--ports", "8101", "--scope", "127.0.0.1", "--authorized", "--profile", "pilot",
                          "--rate", "25", "-o", d)
        files = set(os.listdir(d))
        check("--profile pilot: rate override kept, nessus + evidence pack written",
              "rate 25/s, 50 workers" in out_p and "findings.nessus" in files and any(f.startswith("evidence-") for f in files),
              f"rc={rc_p} {sorted(files)}")
        # 15. evidence pack: signed manifest verifies; one changed byte or an added file fails; secrets are redacted
        import shutil
        signing = shutil.which("ssh-keygen") is not None  # OpenSSH client; CI runners have it
        if not signing:
            print("SKIP evidence pack signature checks: ssh-keygen not installed (unsigned pack still tested)")
        key = os.path.join(tmp, "evkey")
        signers = os.path.join(tmp, "allowed_signers")
        if signing:
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "auditor@example.org", "-f", key], check=True)
            open(signers, "w").write("auditor@example.org " + open(key + ".pub").read().split(" ", 2)[0] + " "
                                     + open(key + ".pub").read().split(" ", 2)[1] + "\n")
        sign_args = ["--sign-key", key] if signing else []
        verify_args = ["--allowed-signers", signers, "--signer-identity", "auditor@example.org"] if signing else []
        d = os.path.join(tmp, "evidence")
        scope_file = os.path.join(tmp, "scope.txt")
        open(scope_file, "w").write("127.0.0.1\n")
        rc_e, out_e = cli("-t", "127.0.0.1", "--ports", "8101", "--scope", scope_file, "--authorized", "-o", d, "--formats", "json,html,csv",
                      "--evidence-pack", *sign_args, "--shodan-key", "SECRET123")
        pack = next(os.path.join(d, f) for f in os.listdir(d) if f.startswith("evidence-") and f.endswith(".zip"))
        import zipfile
        names = zipfile.ZipFile(pack).namelist()
        rc_v, out_v = cli("--verify-pack", pack, *verify_args)
        want = {"results.jsonl", "assets.json", "report.html", "scope/scope.txt", "advisory.json", "command.txt", "manifest.json"}
        check("evidence pack: complete and verifies" + (", signed" if signing else ""),
              rc_v == 0 and (not signing or "signature OK" in out_v) and (want | ({"manifest.json.sig"} if signing else set())) <= set(names),
              f"rc={rc_v} {out_v.strip().splitlines()[-2:]} names={names}")
        check("evidence pack: --shodan-key value redacted", b"SECRET123" not in zipfile.ZipFile(pack).read("command.txt"), "")
        bad = os.path.join(tmp, "tampered.zip")
        with zipfile.ZipFile(pack) as zi, zipfile.ZipFile(bad, "w") as zo:
            for n in zi.namelist():
                data = zi.read(n)
                zo.writestr(n, data.replace(b"LIKELY_VULNERABLE", b"PATCHED_BY_BANNER") if n == "assets.json" else data)
            zo.writestr("extra.txt", b"x")
        rc_t, out_t = cli("--verify-pack", bad, *verify_args)
        check("evidence pack: tampered file and added file detected", rc_t == 1 and "MODIFIED assets.json" in out_t and "ADDED    extra.txt" in out_t,
              f"rc={rc_t}")
        check("--import-local: verdict lands on the scanned asset, out-of-scope file refused",
              [(x["host"], x["final_status"], x["closure"]) for x in a] == [("127.0.0.1", "VERIFIED_VULNERABLE", "OPEN")]
              and "far.json" in out and "not in the approved scope" in out, f"{[(x['host'], x['final_status']) for x in a]} rc={rc}")
    finally:
        mock.kill()
    print("\n" + ("ALL PASSED" if not FAIL else f"{len(FAIL)} FAILED: {FAIL}"))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
