import os, pathlib, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from p2s import assets as A, classify as C, engine as E, enrich as EN, evidence as EV, export as X, fcgi as F, ingest as IN, \
    oracle as O, report as R, verify as V


UBUNTU_PATCHED = ("HOST=a\nBIN=/usr/bin/php8.3|PHP 8.3.6 (cli)\nPKG=php8.3-cli 8.3.6-0ubuntu0.24.04.13\n"
                  "BP=php8.3-common|CVE-2026-109618_109619,CVE-2021-1,\nBP=php-common|\nDONE=1\n")


class T(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(C.classify_version(8, 3, 12, "")[0], "LIKELY_VULNERABLE")
        self.assertEqual(C.classify_version(8, 3, 36, "")[0], "PATCHED_BY_BANNER")
        self.assertEqual(C.classify_version(8, 5, 11, "")[0], "LIKELY_VULNERABLE")
        self.assertEqual(C.classify_version(8, 5, 12, "")[0], "PATCHED_BY_BANNER")
        self.assertEqual(C.classify_version(8, 1, 30, "")[0], "EOL_NO_UPSTREAM_FIX")
        self.assertEqual(C.classify_version(8, 3, 6, "-1ubuntu0.5")[0], "VERIFY_DISTRO_BACKPORT")
        self.assertEqual(C.classify_version(8, 2, 34, "")[0], "LIKELY_VULNERABLE")
        self.assertEqual(C.classify_version(8, 2, 35, "")[0], "PATCHED_BY_BANNER")
        self.assertEqual(C.classify_version(8, 4, 26, "")[0], "LIKELY_VULNERABLE")

    def test_rhel_and_header_distro_hints(self):
        st, conf, note = C.classify_version(8, 2, 13, "", hint="Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k")
        self.assertEqual((st, conf), ("VERIFY_DISTRO_BACKPORT", "low"))
        self.assertIn("Red Hat", note)
        self.assertEqual(C.classify_version(8, 3, 6, "", hint="Apache/2.4.58 (Ubuntu)")[0], "VERIFY_DISTRO_BACKPORT")
        self.assertEqual(C.classify_version(8, 3, 12, "", hint="nginx")[0], "LIKELY_VULNERABLE")
        # 8.3.6 is Ubuntu 24.04's frozen version: patched builds still report it (real changelog observed)
        st, conf, note = C.classify_version(8, 3, 6, "", hint="nginx")
        self.assertEqual((st, conf), ("VERIFY_DISTRO_BACKPORT", "low"))
        self.assertIn("Ubuntu 24.04", note)
        self.assertEqual(C.classify_version(8, 3, 36, "", hint="(CentOS)")[0], "PATCHED_BY_BANNER")
        fp = C.detect([{"path": "/", "status": 200, "headers": {"server": "Apache/2.4.6 (CentOS) PHP/7.4.33",
                        "x-powered-by": "PHP/7.4.33"}, "cookies": [], "body": ""}])
        self.assertEqual(C.banner_status(fp)[:2], ("VERIFY_DISTRO_BACKPORT", "low"))  # EOL upstream, but CentOS may backport
        self.assertEqual(C.classify_version(7, 4, 33, "")[0], "EOL_NO_UPSTREAM_FIX")
        # a distro hint only counts for a branch that distro ships (benchmark: php:8.5.11-apache reports Apache "(Debian)")
        self.assertEqual(C.classify_version(8, 5, 11, "", hint="Apache/2.4.65 (Debian)")[0], "LIKELY_VULNERABLE")
        self.assertEqual(C.classify_version(8, 3, 12, "", hint="Apache/2.4.65 (Debian)")[0], "LIKELY_VULNERABLE")
        self.assertEqual(C.classify_version(8, 2, 29, "", hint="Apache/2.4.62 (Debian)")[0], "VERIFY_DISTRO_BACKPORT")  # bookworm
        self.assertEqual(C.classify_version(7, 4, 33, "", hint="Apache/2.4.56 (Debian)")[0], "VERIFY_DISTRO_BACKPORT")  # bullseye LTS
        self.assertEqual(C.classify_version(8, 5, 11, "", hint="Apache (Red Hat)")[0], "VERIFY_DISTRO_BACKPORT")  # module streams

    def test_advisory_override(self):
        orig = dict(C.ADVISORY)
        try:
            C.set_advisory({"id": "X", "cves": ["CVE-2030-1"], "fixed": {"9.0": "9.0.5"}, "eol_below": "9.0"})
            self.assertEqual(C.classify_version(9, 0, 4, "")[0], "LIKELY_VULNERABLE")
            self.assertEqual(C.classify_version(9, 0, 5, "")[0], "PATCHED_BY_BANNER")
            self.assertEqual(C.classify_version(8, 4, 99, "")[0], "EOL_NO_UPSTREAM_FIX")
            with self.assertRaises(ValueError):
                C.set_advisory({"id": "broken"})
        finally:
            C.set_advisory(orig)
        self.assertEqual(C.CVES, ["CVE-2026-109618", "CVE-2026-109619"])

    def test_invalid_targets_are_all_reported(self):
        with self.assertRaises(E.TargetError) as cm:
            E.parse_targets(["10.0.0.0/33", "good.example.com", "host:99999", "1.2.3.4 customer", "ftp://x.y",
                             "a.b sni=bad_sni!", "999.1.1.1"], [80], 100)
        self.assertEqual(len(cm.exception.problems), 6)
        self.assertTrue(cm.exception.problems[0].startswith("line 1:"))
        eps, _ = E.parse_targets(["[2001:db8::1]:8443", "2001:db8::2"], [80], 100)
        self.assertEqual([(e["host"], e["port"]) for e in eps], [("2001:db8::1", 8443), ("2001:db8::2", 80)])

    def test_http_parsing_and_chunked(self):
        raw = (b"HTTP/1.1 200 OK\r\nServer: x\r\nSet-Cookie: PHPSESSID=1\r\nSet-Cookie: b=2\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n4\r\nwp-c\r\n7\r\nontent!\r\n0\r\n\r\n")
        st, h, ck, body = E.parse_http_response(raw)
        self.assertEqual((st, h["server"], ck, body), (200, "x", ["PHPSESSID=1", "b=2"], "wp-content!"))
        self.assertEqual(E._dechunk(b"5\r\nabc"), b"abc")  # truncated body keeps what arrived
        with self.assertRaises(ValueError):
            E.parse_http_response(b"SSH-2.0-OpenSSH\r\n")
        self.assertEqual(E._host_header("1.2.3.4", None, 8443, True), "1.2.3.4:8443")
        self.assertEqual(E._host_header("::1", None, 80, False), "[::1]")

    def test_hostile_chunked_body_terminates(self):
        # review #1: negative / non-hex chunk sizes used to spin forever
        for body in (b"-6\r\nabc\r\n", b"zz\r\nabc", b"FFFFFFFFFF\r\nx", b"0x10\r\nabc"):
            out = E._dechunk(body)
            self.assertIsInstance(out, bytes)

    def test_duplicate_headers_and_control_chars(self):
        raw = b"HTTP/1.1 200 OK\nX-Powered-By: PleskLin\nX-Powered-By: PHP/8.1.10\x01\n\nbody"  # bare LF too
        st, h, ck, body = E.parse_http_response(raw)
        self.assertEqual(h["x-powered-by"], "PleskLin, PHP/8.1.10")
        fp = C.detect([{"path": "/", "status": st, "headers": h, "cookies": ck, "body": body}])
        self.assertEqual(C.banner_status(fp)[0], "EOL_NO_UPSTREAM_FIX")
        self.assertIsNone(C.VER_RE.search("X-Powered-By: CakePHP/4.4.1"))

    def test_worst_disclosed_version_wins(self):
        fp = C.detect([{"path": "/", "status": 200, "headers": {"x-powered-by": "PHP/8.3.36, PHP/8.1.0"}, "cookies": [], "body": ""}])
        self.assertEqual(C.banner_status(fp)[:3], ("EOL_NO_UPSTREAM_FIX", "high", "8.1.0"))

    def test_final_upstream_release_in_frozen_list_needs_a_hint(self):
        self.assertEqual(C.classify_version(8, 0, 30, "")[0], "EOL_NO_UPSTREAM_FIX")       # vanilla 8.0 final release
        self.assertEqual(C.classify_version(8, 0, 30, "", hint="Apache/2.4.57 (Rocky Linux)")[0], "VERIFY_DISTRO_BACKPORT")
        self.assertEqual(C.classify_version(8, 0, 30, "", hint="nginx")[0], "EOL_NO_UPSTREAM_FIX")

    def test_upstream_repos_are_not_backports(self):
        self.assertEqual(C.classify_version(8, 3, 20, "-1+ubuntu22.04.1+deb.sury.org+1", hint="(Ubuntu)")[0], "LIKELY_VULNERABLE")
        self.assertEqual(C.classify_version(8, 2, 20, "-1.el9.remi")[0], "LIKELY_VULNERABLE")

    def test_exclude_file_with_comments(self):
        # review #5: trailing text on an exclude line silently disabled the exclusion
        eps, _ = E.parse_targets(["10.0.0.0/30"], [80], 10, ["10.0.0.1  prod-db do-not-touch", "# c"])
        self.assertNotIn("10.0.0.1", {e["host"] for e in eps})
        with self.assertRaises(E.TargetError):
            E.parse_targets(["10.0.0.0/30"], [80], 10, ["10.0.0.300"])

    def test_dns_pinning_and_ip_scope(self):
        fake = {"portal.acme.com": ["203.0.113.10"], "cdn.acme.com": ["198.51.100.7"], "dead.acme.com": []}
        eps, _ = E.parse_targets(["portal.acme.com", "cdn.acme.com", "dead.acme.com", "203.0.113.11"], [443], 10)
        pinned, unresolved, answers = E.resolve_endpoints(eps, ["203.0.113.11"], resolver=lambda n: fake[n])
        self.assertEqual(unresolved, ["dead.acme.com"])
        self.assertEqual({(e["host"], e.get("name"), e.get("sni")) for e in pinned},
                         {("203.0.113.10", "portal.acme.com", "portal.acme.com"), ("198.51.100.7", "cdn.acme.com", "cdn.acme.com")})
        sc = E.load_scope(["203.0.113.0/24", "*.acme.com"])
        self.assertEqual(E.out_of_scope(pinned, sc), ["cdn.acme.com -> 198.51.100.7"])  # name ok, IP not approved
        self.assertEqual(E.out_of_scope(pinned, sc, trust_names=True), [])
        # name-only scope: a CNAME to a third party must not be scanned silently -> needs --scope-trust-names
        self.assertEqual(len(E.out_of_scope(pinned, E.load_scope(["*.acme.com"]))), 2)
        self.assertEqual(E.out_of_scope(pinned, E.load_scope(["*.acme.com"]), trust_names=True), [])
        # --resume reuses the first run's answers (round-robin DNS cannot add endpoints)
        again, _, _ = E.resolve_endpoints(eps, resolver=lambda n: ["192.0.2.99"], pinned=answers)
        # pinned answers are reused; only the name that did NOT resolve the first time is asked again
        self.assertEqual({e["host"] for e in again}, {"203.0.113.10", "198.51.100.7", "203.0.113.11", "192.0.2.99"})

    def test_ipv4_only(self):
        eps, _ = E.parse_targets(["www.acme.com"], [443], 10)
        got, _, _ = E.resolve_endpoints(eps, resolver=lambda n: ["203.0.113.10", "2001:db8::10"], ipv4_only=True)
        self.assertEqual([e["host"] for e in got], ["203.0.113.10"])

    def test_dual_stack_name_drops_out_of_scope_address(self):
        eps, _ = E.parse_targets(["www.acme.com"], [443], 10)
        pinned, _, _ = E.resolve_endpoints(eps, resolver=lambda n: ["203.0.113.10", "2001:db8::10"])
        kept, viol, gaps = E.apply_scope(pinned, E.load_scope(["203.0.113.0/24", "www.acme.com"]))
        self.assertEqual(([e["host"] for e in kept], viol), (["203.0.113.10"], []))
        self.assertEqual(gaps, ["www.acme.com -> 2001:db8::10 (address outside approved ranges, skipped)"])

    def test_torn_line_resume(self):
        # review #11: a record appended onto a torn line was lost
        p = os.path.join(tempfile.mkdtemp(), "r.jsonl")
        pathlib.Path(p).write_text('{"key": "a:80", "status": "CLOSED"}\n{"key": "b:80", "sta')
        st = E.Store(p, True)
        st.write({"key": "c:80", "status": "NO_PHP_INDICATOR"})
        st.close()
        self.assertEqual({r["key"] for r in E.load_results(p)}, {"a:80", "c:80"})

    def test_baseline_from_jsonl(self):
        # review #12: --baseline results.jsonl crashed
        p = os.path.join(tempfile.mkdtemp(), "results.jsonl")
        pathlib.Path(p).write_text('{"key": "h:80", "host": "h", "port": 80, "status": "LIKELY_VULNERABLE", "labels": {}}\n'
                           '{"key": "h:443", "host": "h", "port": 443, "status": "CLOSED"}\n')
        self.assertEqual(A.load_assets_any(p)[0]["final_status"], "LIKELY_VULNERABLE")

    def test_scope(self):
        sc = E.load_scope(["10.0.0.0/24  # customer A", "203.0.113.5", "portal.acme.com", "*.acme.net", ""])
        self.assertTrue(E.in_scope("10.0.0.77", sc))
        self.assertFalse(E.in_scope("10.0.1.1", sc))
        self.assertTrue(E.in_scope("203.0.113.5", sc))
        self.assertTrue(E.in_scope("PORTAL.acme.com.", sc))
        self.assertFalse(E.in_scope("evil.acme.com", sc))
        self.assertTrue(E.in_scope("a.b.acme.net", sc))
        self.assertFalse(E.in_scope("acme.net.evil.com", sc))
        eps, _ = E.parse_targets(["10.0.0.0/23"], [80], 4096)
        bad = E.out_of_scope(eps, sc)
        self.assertEqual(len(bad), 255)  # 10.0.1.0-.254 (broadcast excluded) is outside: whole run must abort
        self.assertIsNone(E.load_scope([]))

    def test_store_retries_errors_and_dedupes(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "r.jsonl")
        st = E.Store(p, False)
        st.write({"key": "a:80", "status": "ERROR"})
        st.write({"key": "b:80", "status": "CLOSED"})
        st.close()
        st = E.Store(p, True)
        self.assertEqual(st.done, {"b:80"})  # ERROR is retried on resume
        st.write({"key": "a:80", "status": "NO_PHP_INDICATOR"})
        st.close()
        rs = {r["key"]: r["status"] for r in E.load_results(p)}
        self.assertEqual(rs, {"a:80": "NO_PHP_INDICATOR", "b:80": "CLOSED"})

    def test_incomplete_banner(self):
        r = [{"host": "h", "port": 80, "status": "NO_PHP_INDICATOR", "labels": {}, "key": "h:80", "note": ""}]
        a = A.consolidate(r)
        h = R.html_report(a, A.summarize(a), A.group_table(a), {"generated": "t", "complete": False, "missing": 42}, None, "tr")
        self.assertIn("EKSİK TARAMA: 42", h)
        h = R.html_report(a, A.summarize(a), A.group_table(a), {"generated": "t", "complete": True}, None, "tr")
        self.assertNotIn("EKSİK TARAMA", h)

    def test_targets(self):
        eps, sk = E.parse_targets(["10.0.0.0/30 customer=ACME env=prod", "app.x.com:8443 customer=B", "https://a.b/c",
                                   "10.0.1.5 sni=site.tld ports=443", "# c", ""], [80, 443], 100, ["10.0.0.1"])
        hosts = {e["host"] for e in eps}
        self.assertNotIn("10.0.0.1", hosts)
        self.assertIn("10.0.0.2", hosts)
        self.assertEqual([e for e in eps if e["host"] == "app.x.com"][0]["port"], 8443)
        sni = [e for e in eps if e["host"] == "10.0.1.5"][0]
        self.assertEqual((sni["sni"], sni["port"]), ("site.tld", 443))
        self.assertEqual([e for e in eps if e["host"] == "10.0.0.2"][0]["labels"]["customer"], "ACME")
        _, sk = E.parse_targets(["10.0.0.0/16"], [80], 1000)
        self.assertEqual(sk[0][1], 65536)

    def test_diff(self):
        mk = lambda h, st: {"host": h, "port": 80, "status": st, "labels": {}, "php_version": "", "key": h}
        old = A.consolidate([mk("a", "LIKELY_VULNERABLE"), mk("b", "PATCHED_BY_BANNER"), mk("c", "NO_PHP_INDICATOR"), mk("gone", "LIKELY_VULNERABLE")])
        new = A.consolidate([mk("a", "PATCHED_BY_BANNER"), mk("b", "LIKELY_VULNERABLE"), mk("c", "PATCHED_BY_BANNER"), mk("new", "PHP_VERSION_HIDDEN")])
        d = A.diff(old, new)
        self.assertEqual([x["host"] for x in d["improved"]], ["a"])
        self.assertEqual([x["host"] for x in d["worsened"]], ["b"])
        self.assertEqual([x["host"] for x in d["new_assets"]], ["new"])
        self.assertEqual([x["host"] for x in d["gone_assets"]], ["gone"])
        self.assertEqual(d["unchanged"], 1)  # c: NO_PHP -> PATCHED is not a regression

    def test_verify_overrides_banner(self):
        r = [{"host": "h", "port": 80, "status": "VERIFY_DISTRO_BACKPORT", "labels": {}, "key": "h:80", "php_version": "8.3.6"}]
        ok = {"verdict": "PATCHED_BACKPORT", "summary": "ok", "versions": [{"version": "8.3.6", "patched": True}]}
        self.assertEqual(A.consolidate(r, {"h": ok})[0]["final_status"], "VERIFIED_PATCHED")
        self.assertEqual(A.consolidate(r, {"h": {"verdict": None, "summary": "SSH failed"}})[0]["final_status"], "VERIFY_DISTRO_BACKPORT")

    def test_verify_never_hides_what_the_banner_disclosed(self):
        # review #3: host check says "no PHP" / "patched" but the web banner shows a version the host check never saw
        r = [{"host": "h", "port": 80, "status": "LIKELY_VULNERABLE", "labels": {}, "key": "h:80", "php_version": "8.1.0"}]
        a = A.consolidate(r, {"h": {"verdict": "NO_PHP_FOUND", "summary": "none"}})[0]
        self.assertEqual(a["final_status"], "LIKELY_VULNERABLE")
        self.assertIn("review", a["note"])
        v = {"verdict": "PATCHED", "summary": "x", "versions": [{"version": "8.3.36", "patched": True}]}
        a = A.consolidate(r, {"h": v})[0]
        self.assertEqual(a["final_status"], "LIKELY_VULNERABLE")
        self.assertIn("8.1.0", a["note"])

    def test_open_port_without_http_is_not_reported_as_clean(self):
        r = [{"host": "h", "port": 443, "status": "OPEN_NO_HTTP", "labels": {}, "key": "h:443", "note": "TLS alert"}]
        a = A.consolidate(r)
        self.assertEqual(a[0]["final_status"], "NO_WEB_RESPONSE")
        self.assertFalse(C.is_actionable(a[0]["final_status"]))
        # host verified over SSH but unseen on the web is still listed
        a = A.consolidate([], {"v": {"verdict": "NO_PHP_FOUND", "summary": "none"}})
        self.assertEqual((a[0]["host"], a[0]["final_status"]), ("v", "VERIFIED_NO_PHP"))

    def test_shodan_parse(self):
        doc = {"data": [{"data": "HTTP/1.1 200\r\nX-Powered-By: PHP/8.3.12\r\n"}]}
        self.assertEqual(EN.parse_shodan_host(doc)["status"], "LIKELY_VULNERABLE")
        self.assertIsNone(EN.parse_shodan_host({"data": [{"data": "nginx"}]}))

    def test_verify_ssh_failure_and_runner(self):
        ok = "HOST=a\nBIN=/usr/bin/php|PHP 8.3.36 (cli)\nDONE=1\n"
        out = V.verify_hosts(["x", "y"], {}, "u", None, runner=lambda t, k, n, p, **kw: (0, ok, "") if t == "u@x" else (255, "", "denied"))
        self.assertEqual(out["x"]["verdict"], "PATCHED")
        self.assertIsNone(out["y"]["verdict"])

    def test_verify_ignores_removed_package_records(self):
        # real-world: dpkg lists 'php-crypt-gpg' with no version (not installed) on hosts without PHP
        d = V.parse_output("HOST=a\nPKG=php-crypt-gpg \nDONE=1\n")
        self.assertEqual(V.verdict(d)[0], "NO_PHP_FOUND")
        d = V.parse_output("HOST=a\nPKG=php8.3-cli 8.3.6-0ubuntu0.24.04.5\nDONE=1\n")
        self.assertEqual(V.verdict(d)[0], "REVIEW")

    def test_backport_token_expansion(self):
        self.assertEqual(V.expand_cve_tokens(["CVE-2026-109618_109619", "CVE-2026-109618"]),
                         ["CVE-2026-109618", "CVE-2026-109619"])
        d = V.parse_output(UBUNTU_PATCHED)
        self.assertEqual(d["backport"], {"8.3": {"CVE-2026-109618", "CVE-2026-109619"}})
        self.assertEqual(V.verdict(d)[0], "PATCHED_BACKPORT")
        self.assertIn("109618|109619", V.remote_script())

    def test_backport_evidence_is_scoped_to_its_own_package(self):
        # review #2: a patched distro changelog must not vouch for other builds on the same host
        for extra, culprit in (("BIN=/usr/local/bin/php|PHP 8.1.0 (cli)", "/usr/local/bin/php"),
                               ("CT=web|php:8.2-fpm|PHP 8.2.10 (fpm-fcgi)", "container:web"),
                               ("BIN=/usr/bin/php7.4|PHP 7.4.3 (cli)\nPKG=php7.4-cli 7.4.3-4ubuntu2.24", "/usr/bin/php7.4"),
                               ("BIN=/opt/cpanel/ea-php83/root/usr/bin/php|PHP 8.3.6 (cli)", "ea-php83")):
            v, summary, _ = V.verdict(V.parse_output(UBUNTU_PATCHED.replace("DONE=1", extra + "\nDONE=1")))
            self.assertTrue(v.startswith("VULNERABLE"), (extra, v))
            self.assertIn(culprit, summary)
        # same branch, but the binary is not the installed package version -> no coverage
        d = V.parse_output(UBUNTU_PATCHED.replace("PHP 8.3.6 (cli)", "PHP 8.3.4 (cli)"))
        self.assertEqual(V.verdict(d)[0], "VULNERABLE")

    def test_unversioned_runtimes_need_review(self):
        d = V.parse_output("HOST=a\nBIN=/usr/bin/php|PHP 8.3.36 (cli)\nBIN=/usr/local/bin/frankenphp|\nDONE=1\n")
        self.assertEqual(V.verdict(d)[0], "REVIEW")
        d = V.parse_output("HOST=a\nBIN=/usr/local/bin/frankenphp|FrankenPHP v1.4.0 PHP 8.4.27 Caddy v2.9.1\nDONE=1\n")
        self.assertEqual(V.verdict(d)[0], "PATCHED")
        d = V.parse_output("HOST=a\nAPACHE_MOD= php_module (shared)\nDONE=1\n")
        self.assertEqual(V.verdict(d)[0], "REVIEW")

    def test_truncated_binary_list_needs_review(self):
        d = V.parse_output("HOST=a\nTRUNCATED=binaries\nBIN=/usr/bin/php|PHP 8.3.36 (cli)\nDONE=1\n")
        self.assertEqual(V.verdict(d)[0], "REVIEW")

    def test_collector_limits_are_never_silent(self):
        for marker in ("containers", "processes"):
            d = V.parse_output(f"HOST=a\nTRUNCATED={marker}\nBIN=/usr/bin/php|PHP 8.3.36 (cli)\nDONE=1\n")
            self.assertEqual(V.verdict(d)[0], "REVIEW", marker)

    def test_pinned_dns_empty_or_tampered_answers_are_re_resolved(self):
        eps, _ = E.parse_targets(["a.acme.com", "b.acme.com"], [80], 10)
        got, unresolved, _ = E.resolve_endpoints(eps, resolver=lambda n: ["203.0.113.5"],
                                                 pinned={"a.acme.com": [], "b.acme.com": ["not-an-ip; rm -rf /"]})
        self.assertEqual(({e["host"] for e in got}, unresolved), ({"203.0.113.5"}, []))

    def test_ssh_map_validation(self):
        p = os.path.join(tempfile.mkdtemp(), "m")
        pathlib.Path(p).write_text("h1 u@1.2.3.4 port=22\nh2 u@1.2.3.5 port=abc\n")
        with self.assertRaises(ValueError):
            V.load_ssh_map(p)
        pathlib.Path(p).write_text("h1 -oProxyCommand=x\n")
        with self.assertRaises(ValueError):
            V.load_ssh_map(p)

    def test_report_escaping(self):
        r = [{"host": "h", "port": 80, "status": "LIKELY_VULNERABLE", "labels": {"customer": "<b>x</b>"}, "key": "h:80",
              "php_version": "<script>alert(1)</script>", "server": "=cmd", "note": "n", "cms_hint": "", "indicators": []}]
        a = A.consolidate(r)
        h = R.html_report(a, A.summarize(a), A.group_table(a), {"generated": "t"}, None, "en")
        self.assertNotIn("<script>alert(1)</script>", h)
        self.assertNotIn("<b>x</b>", h)
        self.assertEqual(R.safe_cell("=cmd"), "'=cmd")
        self.assertEqual(R.safe_cell("@x"), "'@x")
        self.assertEqual(R.safe_cell("\t=HYPERLINK(1)"), "'\t=HYPERLINK(1)")
        self.assertEqual(R.safe_cell("PHP/8.1.0\x01"), "PHP/8.1.0")


# Response bodies captured from php:8.5.11-apache / php:8.5.12-apache (tests/oracle_lab.py), trimmed.
W = "<br />\n<b>Warning</b>:  PHP Request Startup: "
PRE_FIX = (W + "Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9 ... in <b>Unknown</b> on line <b>0</b><br />\n"
           + W + "Failed to read session data: files (path: ) in <b>Unknown</b> on line <b>0</b><br />\n"
           + W + "Failed to write session data (files). Please verify that the current setting of session.save_path is correct () "
           "in <b>Unknown</b> on line <b>0</b><br />\nlab")
FIXED = PRE_FIX.split(W + "Failed to write")[0] + "lab"


class Discovery(unittest.TestCase):
    def test_harvest_php_links(self):
        body = ('<a href="search.php?q=1">s</a><form action="/login.php"></form><a href="https://shop.acme.test/cart.php">c</a>'
                '<a href="https://evil.test/x.php">x</a><a href="javascript:a.php">j</a><a href="../up.php">u</a>'
                '<a href="search.php">dup</a><img src="pic.png">')
        self.assertEqual(C.harvest_php_links(body, {"shop.acme.test"}, "/app/home"),
                         ["/app/search.php", "/login.php", "/cart.php"])
        self.assertEqual(C.harvest_php_links(body, set(), "/app/home", limit=10)[-1], "/up.php")
        self.assertEqual(C.harvest_php_links("", set()), [])

    def test_app_content_not_status_proves_php(self):
        r = lambda path, status, body, headers=None: {"path": path, "status": status, "headers": headers or {}, "cookies": [], "body": body}
        wp = [r("/", 200, "<html>home</html>"), r("/wp-login.php", 200, '<input id="user_login">')]
        fp = C.detect(wp, ["/wp-login.php"])
        self.assertIn("app:WordPress", fp["indicators"])
        self.assertEqual(C.banner_status(fp)[0], "PHP_VERSION_HIDDEN")
        # a 200 without the content (SPA / catch-all) proves nothing; a bare .php 200 is ignored on a catch-all server
        spa = [r("/", 200, "<div id=app>"), r("/wp-login.php", 200, "<div id=app>"), r("/index.php", 200, "<div id=app>")]
        self.assertEqual(C.detect(spa, ["/wp-login.php", "/index.php"], catch_all=True)["indicators"], [])
        self.assertIn("path:/index.php", C.detect(spa, ["/index.php"])["indicators"])
        # a redirect into a .php script is server-side PHP routing
        self.assertIn("redirect:.php", C.detect([r("/", 302, "", {"location": "/portal/login.php?next=/"})])["indicators"])
        self.assertNotIn("redirect:.php", C.detect([r("/", 302, "", {"location": "/php/"})])["indicators"])


class FastCGI(unittest.TestCase):
    def test_requests_are_benign(self):
        recs = F.parse_records(F.missing_script_request())
        self.assertEqual([t for t, _ in recs], [F.BEGIN, F.PARAMS, F.PARAMS, F.STDIN])
        params = F._decode_pairs(recs[1][1])
        self.assertTrue(params["SCRIPT_FILENAME"].startswith("/nonexistent/p2s-"))
        self.assertFalse({"PHP_VALUE", "PHP_ADMIN_VALUE"} & set(params))  # never the knobs that make FPM run code
        self.assertEqual(F.parse_records(F.get_values_request())[0][0], F.GET_VALUES)

    def test_interpret(self):
        values = F.record(F.GET_VALUES_RESULT, 0, F._pairs([("FCGI_MPXS_CONNS", "0")]))
        script = (F.record(F.STDOUT, 1, b"Status: 404 Not Found\r\nX-Powered-By: PHP/8.4.26\r\n\r\nFile not found.\n")
                  + F.record(F.END, 1, b"\0" * 8))
        f = F.interpret(values, script)
        self.assertEqual((f["fastcgi"], f["php"], f["php_version"]), (True, True, "8.4.26"))
        st, conf, note = C.fpm_status(f)
        self.assertEqual((st, conf), ("FPM_EXPOSED", "high"))
        self.assertIn("Likely vulnerable", note)
        self.assertTrue(C.is_actionable("FPM_EXPOSED"))
        self.assertEqual(C.rank("FPM_EXPOSED"), 0)
        f = F.interpret(values, b"")  # FastCGI, but no PHP evidence
        self.assertEqual((f["fastcgi"], f["php"], C.fpm_status(f)[1]), (True, False, "medium"))
        self.assertFalse(F.interpret(b"SSH-2.0-x\r\n", b"")["fastcgi"])
        self.assertEqual(F.parse_records(b"\x01\x06\x00\x01\xff\xff\x00\x00short"), [])  # truncated record is dropped


MIT_OUT = """HOST=h
INISET=/etc/php/8.3/apache2/php.ini
INISET=/etc/php/8.3/fpm/php.ini
INISET=/etc/php/8.3/cli/php.ini
INI=/etc/php/8.3/apache2/php.ini|session.upload_progress.enabled = On
INI=/etc/php/8.3/apache2/php.ini|session.upload_progress.enabled = Off ; conf.d/99 wins
INI=/etc/php/8.3/fpm/php.ini|file_uploads = Off
INI=/etc/php/8.3/cli/php.ini|session.upload_progress.enabled = On
POOL=/etc/php/8.3/fpm/pool.d/shop.conf:php_admin_flag[file_uploads] = on
IP=10.0.0.5
DONE=1
"""


class HostSide(unittest.TestCase):
    def test_mitigation_per_sapi_and_pool(self):
        m = V.mitigation(V.parse_output(MIT_OUT))
        self.assertEqual(m["sets"]["/etc/php/8.3/apache2/php.ini"]["blocked_by"], "session.upload_progress.enabled")  # last wins
        self.assertNotIn("/etc/php/8.3/cli/php.ini", m["sets"])  # CLI is not web-facing
        self.assertEqual(m["sets"]["/etc/php/8.3/fpm/php.ini"]["pools"], {"/etc/php/8.3/fpm/pool.d/shop.conf": ""})
        self.assertIs(m["state"], False)  # one FPM pool re-enables uploads
        ok = V.mitigation(V.parse_output(MIT_OUT.replace("php_admin_flag[file_uploads] = on", "php_admin_flag[file_uploads] = off")))
        self.assertIs(ok["state"], True)
        apache = V.mitigation(V.parse_output(MIT_OUT.replace("POOL=", "#").replace(
            "IP=", "APACHEINI=php_admin_flag session.upload_progress.enabled On\nIP=")))
        self.assertIs(apache["state"], False)
        self.assertIs(V.mitigation(V.parse_output("DONE=1\n"))["state"], None)
        self.assertEqual(V.parse_output(MIT_OUT)["ips"], ["10.0.0.5"])

    def test_ioc_parsing_and_completeness(self):
        out = ("IOC_PRIV=root\nIOC_SINCE=2026-09-21\nIOC_ROOT=/var/www/html\n"
               "IOC_RECENT=/var/www/html/a|b.php|2026-10-22 10:00:00.000 +0000|42|" + "a" * 64 + "\n"
               "IOC_SHELL=/var/www/html/up/x.php\nIOC_CHILD=  9 191 sh sh -c id\nDONE=1\n")
        ioc = V.parse_output(out)["ioc"]
        self.assertEqual(ioc["recent"][0]["path"], "/var/www/html/a|b.php")  # a '|' in a file name stays in the path
        hits, complete, text = V.ioc_summary(ioc)
        self.assertEqual((len(hits), complete), (2, True))
        self.assertIn("2 hit(s)", text)
        _, complete, text = V.ioc_summary(V.parse_output(out.replace("IOC_PRIV=root", "IOC_PRIV=user"))["ioc"])
        self.assertFalse(complete)
        self.assertIn("not root", text)
        trunc = V.parse_output(out + "TRUNCATED=ioc_recent\n")
        self.assertFalse(V.ioc_summary(trunc["ioc"])[1])
        self.assertNotIn("ioc_recent", trunc.get("truncated", set()))  # IoC truncation must not turn the PHP verdict to REVIEW
        self.assertEqual(V.ioc_summary(None), ([], False, ""))

    def test_collector_date_is_validated(self):
        self.assertIn("SINCE='2026-09-21'", V.remote_script("2026-09-21"))
        self.assertNotIn("IOC_", V.remote_script())
        with self.assertRaises(ValueError):
            V.remote_script("2026-09-21'; id; '")

    def test_closure(self):
        mk = lambda st, verified=None: {"final_status": st, "verified": verified}
        ioc_ok = {"ioc": {"hits": [], "complete": True}}
        cases = [(mk("VERIFIED_PATCHED", ioc_ok), "CLOSED_VERIFIED"),
                 (mk("VERIFIED_PATCHED", {"ioc": {"hits": [], "complete": False}}), "CLOSED_IOC_PENDING"),
                 (mk("VERIFIED_PATCHED"), "CLOSED_IOC_PENDING"),
                 (mk("VERIFIED_PATCHED", {"ioc": {"hits": ["webshell"], "complete": True}}), "COMPROMISE_SUSPECTED"),
                 (mk("VERIFIED_VULNERABLE", {"mitigation": {"state": True}}), "OPEN_MITIGATED"),
                 (mk("VERIFIED_VULNERABLE", {"mitigation": {"state": False}}), "OPEN"),
                 (mk("FPM_EXPOSED", {"mitigation": {"state": True}}), "OPEN"),  # an ini knob does not close an open socket
                 (mk("VERIFIED_RESTART_REQUIRED"), "PENDING_RESTART"),
                 (mk("ORACLE_PATCHED"), "CLOSED_REMOTE"), (mk("NO_PHP_INDICATOR"), "NO_PHP_EVIDENCE"),
                 (mk("VERIFIED_NO_PHP"), "NOT_APPLICABLE")]
        for a, want in cases:
            self.assertEqual(A.closure(a), want, a)
        self.assertEqual(set(C.CLOSURE), {w for _, w in cases} | {"OPEN"})
        # a patched host with IoC hits needs action even though its status is not actionable
        r = [{"host": "h", "port": 80, "status": "PATCHED_BY_BANNER", "labels": {}, "key": "h:80", "php_version": "8.3.36"}]
        v = {"verdict": "PATCHED", "summary": "ok", "versions": [{"version": "8.3.36", "patched": True}],
             "ioc": {"hits": ["webshell: /x.php"], "complete": True}}
        a = A.consolidate(r, {"h": v})
        self.assertEqual((a[0]["closure"], A.summarize(a)["actionable"]), ("COMPROMISE_SUSPECTED", 1))

    def test_local_document(self):
        doc = {"format": "php2shell.local/1", "collected_at": "t", "output": MIT_OUT}
        rec, ips = V.load_local(doc)
        self.assertEqual((rec["source"], ips, rec["checked_at"]), ("local", ["10.0.0.5"], "t"))
        for bad in ({"format": "other", "output": MIT_OUT}, {"format": "php2shell.local/1", "output": "HOST=x"}, []):
            with self.assertRaises(ValueError):
                V.load_local(bad)


class Integrations(unittest.TestCase):
    def test_targets_from(self):
        import json as j
        nuclei = "\n".join(j.dumps(x) for x in [
            {"template-id": "CVE-2026-109618", "host": "https://shop.acme.test", "matched-at": "https://shop.acme.test:8443/index.php"},
            {"template-id": "php-detect", "host": "https://shop.acme.test", "matched-at": "https://shop.acme.test:8443/"},
            {"template-id": "x", "ip": "2001:db8::5", "port": "80"}])
        lines, kind = IN.target_lines(nuclei)
        self.assertEqual(kind, "nuclei")
        self.assertEqual(lines, ["https://shop.acme.test:8443/ external=nuclei:CVE-2026-109618+nuclei:php-detect",
                                 "http://[2001:db8::5]:80/ external=nuclei:x"])
        eps, _ = E.parse_targets(lines, [80], 10)
        self.assertEqual((eps[0]["port"], eps[0]["labels"]["external"]), (8443, "nuclei:CVE-2026-109618+nuclei:php-detect"))
        shodan = j.dumps({"ip_str": "203.0.113.9", "port": 443, "ssl": {}, "data": "HTTP/1.1 200\r\nX-Powered-By: PHP/8.3.12"})
        self.assertEqual(IN.target_lines(shodan), (["https://203.0.113.9:443/ external=shodan:PHP/8.3.12"], "shodan"))
        for bad in ("not json", j.dumps({"foo": 1}), ""):
            with self.assertRaises(ValueError):
                IN.target_lines(bad)
        hostile = j.dumps({"template-id": "a b;rm -rf", "host": "http://h.test"})
        self.assertNotIn(" ", IN.target_lines(hostile)[0][0].split(" ", 1)[1])  # label cannot inject extra tokens

    def test_exports(self):
        import xml.etree.ElementTree as ET
        r = [{"host": "10.0.0.5", "port": 80, "status": "LIKELY_VULNERABLE", "scheme": "http", "labels": {}, "key": "a", "php_version": "8.3.12"},
             {"host": "10.0.0.5", "port": 9000, "status": "FPM_EXPOSED", "scheme": "fastcgi", "labels": {}, "key": "b", "php_version": ""},
             {"host": "10.0.0.6", "port": 80, "status": "PATCHED_BY_BANNER", "scheme": "http", "labels": {}, "key": "c", "php_version": "8.3.36"},
             {"host": "10.0.0.7", "port": 80, "status": "LIKELY_VULNERABLE", "scheme": "http", "labels": {}, "key": "d", "php_version": "8.3.1"}]
        v = {"10.0.0.7": {"verdict": "PATCHED", "summary": "ok", "versions": [{"version": "8.3.1", "patched": True}]}}
        assets = A.consolidate(r, v)
        fs = X.findings(assets, "tr")
        self.assertEqual(sorted((f["host"], f["kind"], f["severity"]) for f in fs),
                         [("10.0.0.5", "fpm", "critical"), ("10.0.0.5", "vuln", "high")])  # .6 patched; .7 host-verified patched wins
        root = ET.fromstring(X.nessus(assets, "tr"))
        items = root.findall(".//ReportItem")
        self.assertEqual(sorted(i.get("severity") for i in items), ["3", "4"])
        self.assertTrue(all(i.find("solution").text.endswith("tavsiye edilir.") for i in items))
        self.assertEqual(len({f["id"] for f in fs}), 2)
        self.assertEqual(X.findings(assets, "tr")[0]["id"], fs[0]["id"])  # stable across runs
        sar = X.sarif(assets)
        self.assertEqual((sar["version"], len(sar["runs"][0]["results"])), ("2.1.0", 2))
        dojo = X.defectdojo(assets)["findings"]
        self.assertEqual(sorted(d["severity"] for d in dojo), ["Critical", "High"])
        self.assertEqual(X.findings_doc(assets, A.summarize(assets), {"generated": "t"})["format"], "php2shell.findings/1")
        hostile = A.consolidate([dict(r[0], host="10.0.0.9", php_version="8.1.0</description><x>")])
        ET.fromstring(X.nessus(hostile, "en"))  # banner text is escaped: still well-formed XML

    def test_windows_collector_output(self):
        # the line format p2s/collect_windows.ps1 emits (IIS + php-cgi, admin, -Ioc); parsed by the same code as Linux
        out = ("HOST=WEB01\nOS=Microsoft Windows Server 2022 Standard 10.0.20348\n"
               "IIS_FASTCGI=C:\\PHP\\php-cgi.exe\nBIN=C:\\PHP\\php-cgi.exe|PHP 8.3.12 (cgi-fcgi) (built: Sep 24 2026 10:00:00) (NTS Visual C++ 2019 x64)\n"
               "BIN=C:\\PHP\\php.exe|PHP 8.3.12 (cli) (built: Sep 24 2026 10:00:00) (NTS Visual C++ 2019 x64)\nIP=10.0.0.20\n"
               "INISET=C:\\PHP\\php.ini\nINI=C:\\PHP\\php.ini|session.upload_progress.enabled = Off\n"
               "IOC_PRIV=root\nIOC_SINCE=2026-09-21\nIOC_ROOT=C:\\inetpub\\wwwroot\n"
               "IOC_CHILD=4120 5512 cmd.exe cmd /c whoami\nDONE=1\n")
        rec, ips = V.load_local({"format": "php2shell.local/1", "platform": "windows", "output": out})
        self.assertEqual((rec["verdict"], ips, rec["mitigation"]["state"]), ("VULNERABLE", ["10.0.0.20"], True))
        self.assertEqual(rec["ioc"]["hits"], ["shell/network tool spawned by a PHP worker: 4120 5512 cmd.exe cmd /c whoami"])
        self.assertIn("collect_windows", " ".join(n for n in os.listdir(os.path.join(os.path.dirname(__file__), "..", "p2s"))))

    def test_sla(self):
        from datetime import date
        mk = lambda h, st, owner="": {"host": h, "port": 80, "status": st, "labels": {"owner": owner} if owner else {}, "key": h,
                                      "php_version": ""}
        week1 = A.consolidate([mk("a", "LIKELY_VULNERABLE", "ops@acme"), mk("b", "VERIFY_DISTRO_BACKPORT"), mk("c", "PATCHED_BY_BANNER")])
        A.apply_sla(week1, None, date(2026, 10, 1))
        sa = {x["host"]: x.get("sla") for x in week1}
        self.assertEqual((sa["a"]["first_seen"], sa["a"]["due"], sa["a"]["owner"]), ("2026-10-01", "2026-10-08", "ops@acme"))  # high: 7
        self.assertEqual(sa["b"]["due"], "2026-10-15")  # medium: 14
        self.assertIsNone(sa["c"])
        # a week later: the clock did not restart; a fixed asset is stamped closed; compromise counts as critical
        v = {"c": {"verdict": "PATCHED", "summary": "x", "versions": [{"version": "8.3.36", "patched": True}],
                   "ioc": {"hits": ["webshell"], "complete": True}}}
        week2 = A.consolidate([mk("a", "LIKELY_VULNERABLE", "ops@acme"), mk("b", "PATCHED_BY_BANNER"), mk("c", "PATCHED_BY_BANNER")], v)
        A.apply_sla(week2, week1, date(2026, 10, 12), A.parse_sla("critical=1"))
        sb = {x["host"]: x.get("sla") for x in week2}
        self.assertEqual((sb["a"]["first_seen"], sb["a"]["overdue_days"]), ("2026-10-01", 4))
        self.assertEqual(sb["b"], {"first_seen": "2026-10-01", "owner": "", "closed_on": "2026-10-12"})
        self.assertEqual((sb["c"]["days"], sb["c"]["first_seen"]), (1, "2026-10-12"))
        s = A.summarize(week2)
        self.assertEqual((s["overdue"], s["max_overdue_days"]), (1, 4))
        for bad in ("low=3", "critical=x", "critical"):
            with self.assertRaises(ValueError):
                A.parse_sla(bad)

    def test_new_advisory_is_data_only(self):
        import json as j
        orig = j.loads(j.dumps(C.ADVISORY))
        future = {"id": "PHP-NEXT", "cves": ["CVE-2027-000001"], "published": "2027-02-01", "fixed": {"8.3": "8.3.40", "8.4": "8.4.31"},
                  "texts": {"en": {"vuln_title": "PHP-NEXT: heap overflow ({cves})", "title": "PHP-NEXT exposure report"}},
                  "eol_below": "8.3", "sources": [["php.net", "https://www.php.net/"]], "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        self.assertEqual(C.validate_advisory(future), ([], []))
        try:
            C.set_advisory(future)
            self.assertEqual(C.classify_version(8, 3, 36, "")[0], "LIKELY_VULNERABLE")  # patched for PHP2Shell, not for this one
            self.assertEqual(C.classify_version(8, 4, 31, "")[0], "PATCHED_BY_BANNER")
            self.assertEqual(C.classify_version(8, 2, 35, "")[0], "EOL_NO_UPSTREAM_FIX")
            self.assertIn("PHP-NEXT: heap overflow (CVE-2027-000001)", X.nessus(A.consolidate([{"host": "h", "port": 80,
                          "status": "LIKELY_VULNERABLE", "labels": {}, "key": "h", "php_version": "8.3.36", "scheme": "http"}]), "en"))
            self.assertIn("<title>PHP-NEXT exposure report</title>", R.html_report([], A.summarize([]), [], {"generated": "t"}, None, "en"))
            self.assertIn("CVE-2027-000001", X.nessus(A.consolidate([{"host": "h", "port": 80, "status": "LIKELY_VULNERABLE", "labels": {},
                                                                     "key": "h", "php_version": "8.3.36", "scheme": "http"}]), "en"))
        finally:
            C.set_advisory(orig)
        bad = dict(future, fixed={"8.3": "8.4.1", "x": "1"}, cves=["CVE-1"], cvss3_vector="CVSS:4.0/AV:N", sources=[["n", "http://x"]])
        errs, _ = C.validate_advisory(bad)
        self.assertEqual(len(errs), 5, errs)
        self.assertIn("eol_below", " ".join(C.validate_advisory(dict(future, eol_below="8.2"))[1]))
        self.assertEqual(C.ADVISORY.get("oracle"), "session-write")  # only the built-in advisory carries the oracle
        self.assertTrue(C.validate_advisory(dict(future, oracle="guess"))[0])

    def test_evidence_redaction(self):
        self.assertEqual(EV.redact_argv(["-t", "x", "--shodan-key", "K", "--shodan-key=K2"]),
                         ["-t", "x", "--shodan-key", "<redacted>", "--shodan-key=<redacted>"])


class Oracle(unittest.TestCase):
    def test_evaluate(self):
        self.assertEqual(O.evaluate(PRE_FIX), ("VULNERABLE", 3, "files"))
        self.assertEqual(O.evaluate(FIXED), ("PATCHED", 2, "files"))
        plain = PRE_FIX.replace("<br />", "").replace("<b>", "").replace("</b>", "")  # html_errors=0
        self.assertEqual(O.evaluate(plain)[0], "VULNERABLE")
        self.assertEqual(O.evaluate("lab"), ("SILENT", 0, ""))
        # PHP 7.x words the first warning differently (captured from php:7.4-apache)
        php7 = PRE_FIX.replace("Session ID is too long", "The session id is too long")
        self.assertEqual(O.evaluate(php7)[0], "VULNERABLE")
        self.assertEqual(O.evaluate(PRE_FIX.split(W + "Failed to read")[0])[0], "PARTIAL")
        # a 2/3 answer only means "fixed" for the handler the lab validated
        self.assertEqual(O.evaluate(FIXED.replace("data: files", "data: memcached"))[0], "UNVALIDATED")

    def test_request_shape(self):
        self.assertEqual(O.session_names(["PHPSESSID=abc; path=/", "LABSID=x", "laravel_session=y", "lang=tr"]),
                         ["PHPSESSID", "LABSID", "laravel_session"])
        self.assertEqual(len(O.session_names([f"sid{i}=1" for i in range(10)])), O.MAX_NAMES)
        ctype, cookie, body = O.build(["PHPSESSID", "LABSID"])
        self.assertEqual(cookie, "PHPSESSID=_; LABSID=_")
        b = ctype.split("boundary=")[1].encode()
        self.assertTrue(body.startswith(b"--" + b) and body.endswith(b"--" + b + b"--\r\n"))
        # the progress field must precede the file part, or PHP never starts the upload-progress session
        self.assertLess(body.index(b'name="PHP_SESSION_UPLOAD_PROGRESS"'), body.index(b'filename="p2s.txt"'))
        self.assertLess(len(body), 600)
        self.assertNotEqual(O.build(["PHPSESSID"])[2], O.build(["PHPSESSID"])[2])

    def test_apply_oracle(self):
        ev = lambda body: dict(zip(("result", "markers", "handler"), O.evaluate(body)), path="/")
        st, conf, note = C.apply_oracle("PATCHED_BY_BANNER", "medium", "", ev(PRE_FIX))
        self.assertEqual((st, conf), ("ORACLE_VULNERABLE", "high"))  # the running process outranks the banner
        self.assertIn("Banner said", note)
        for banner in ("VERIFY_DISTRO_BACKPORT", "PHP_VERSION_HIDDEN", "NO_PHP_INDICATOR", "PATCHED_BY_BANNER"):
            self.assertEqual(C.apply_oracle(banner, "low", "", ev(FIXED))[0], "ORACLE_PATCHED")
        for banner in ("LIKELY_VULNERABLE", "EOL_NO_UPSTREAM_FIX"):  # disclosed vulnerable version: conflict, not "patched"
            st, _, note = C.apply_oracle(banner, "high", "n", ev(FIXED))
            self.assertEqual(st, banner)
            self.assertIn("Conflict", note)
        st, conf, note = C.apply_oracle("VERIFY_DISTRO_BACKPORT", "low", "n", ev("lab"))
        self.assertEqual((st, conf), ("VERIFY_DISTRO_BACKPORT", "low"))
        self.assertIn("not evidence", note)
        self.assertEqual(C.apply_oracle("LIKELY_VULNERABLE", "high", "n", None), ("LIKELY_VULNERABLE", "high", "n"))
        self.assertTrue(C.is_actionable("ORACLE_VULNERABLE"))
        self.assertTrue(C.is_actionable("PHP_VERSION_HIDDEN"))
        self.assertFalse(C.is_actionable("ORACLE_PATCHED"))

    def test_host_check_does_not_hide_a_running_pre_fix_build(self):
        r = [{"host": "h", "port": 80, "status": "ORACLE_VULNERABLE", "labels": {}, "key": "h:80", "php_version": ""}]
        v = {"verdict": "PATCHED_BACKPORT", "summary": "ok", "versions": [{"version": "8.3.6", "patched": True}]}
        a = A.consolidate(r, {"h": v})[0]
        self.assertEqual(a["final_status"], "ORACLE_VULNERABLE")
        self.assertIn("not restarted", a["note"])

    def test_report_declares_the_active_check(self):
        r = [{"host": "h", "port": 80, "status": "ORACLE_PATCHED", "labels": {}, "key": "h:80", "php_version": "",
              "note": "n", "cms_hint": "", "indicators": []}]
        a = A.consolidate(r)
        for meta, passive in (({"generated": "t"}, True), ({"generated": "t", "oracle": True}, False)):
            h = R.html_report(a, A.summarize(a), A.group_table(a), meta, None, "en")
            self.assertEqual("No exploit, memory-exhaustion or multipart trigger traffic is sent" in h, passive)
            self.assertEqual("--oracle" in h, not passive)


if __name__ == "__main__":
    unittest.main()
