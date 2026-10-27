# php2shell-scanner

Exposure triage, host verification and remediation tracking for **CVE-2026-109618 / CVE-2026-109619 (PHP2Shell)** —
the PHP core unauthenticated remote-code-execution flaws fixed in PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 on 2026-10-21.

Most PHP2Shell scanners answer one question from a banner: *does the version look vulnerable?* That answer is wrong on
distribution backports and silent on hosts that hide their version. php2shell-scanner is built to answer the question
that follows: **is the exposure closed, on every asset, and can you prove it?**

- **Distribution backports are not false alarms.** Ubuntu 24.04 shipped the fix as `8.3.6-0ubuntu0.24.04.13`, which
  still reports `PHP/8.3.6`. Banner-only tools flag it as vulnerable; this tool marks it "verify" and settles it from
  package changelogs on the host — or remotely with `--oracle`.
- **The running process, not the package.** An upgraded package does nothing until PHP workers restart (and Apache
  `graceful`/`reload` is not enough for mod_php). The tool detects replaced binaries still running on the host, and
  `--oracle` sees the running code from the network.
- **Exposed PHP-FPM.** A FastCGI port reachable from the network is remote code execution on its own; it is found and
  ranked first.
- **Closure, not just detection.** Per asset: open / mitigated / restart pending / closed and verified / compromise
  suspected, remediation deadlines, a weekly diff, and a signed evidence pack an auditor can check.
- **Safe by design.** GET requests by default, a mandatory approved scope with DNS pinning, rate limiting everywhere, no
  exploit or crash traffic.

A single file, Python 3.9+, no mandatory dependencies.

## Responsible use

Scan only systems you own or have **written authorization** to assess. The tool enforces `--scope` and requires
`--authorized`, but those switches do not create authorization — you do. `--oracle` sends active (non-exploit) requests
and `--verify` / `--local` / `--ioc` run read-only commands on hosts: use them only where your authorization covers
them. Banner results are triage, not proof. Provided under the MIT License, without warranty.

## Install

Download `php2shell.pyz` from the [latest release](https://github.com/erdemkayar/php2shell-scan/releases/latest) and
check its SHA-256 against the release notes, or build it from source:

```
git clone https://github.com/erdemkayar/php2shell-scan.git && cd php2shell-scan
sh build.sh          # runs the unit tests, writes php2shell.pyz
python3 php2shell.pyz --version
```

Optional extras: `python3 -m pip install --user openpyxl python-docx cryptography` (Excel, Word, TLS certificate names).

## Quick start

```
# targets.txt: one IP / CIDR / host / URL per line, optional labels (customer=ACME owner=ops@acme.example ...)
# scope.txt:   the ranges the owner approved
python3 php2shell.pyz -t targets.txt --scope scope.txt --list                          # count + duration, no traffic
python3 php2shell.pyz -t targets.txt --scope scope.txt --authorized -o out/acme        # scan -> out/acme/report.html
python3 php2shell.pyz -t targets.txt --scope scope.txt --authorized -o out/acme --verify --ssh-map ssh_map.txt
python3 php2shell.pyz -t targets.txt --scope scope.txt --authorized -o out/acme-w44 --baseline out/acme/assets.json
```

Exit codes: `0` nothing actionable · `2` actionable assets · `3` coverage incomplete · `1` error / out-of-scope target.

## What it does

| Capability | How |
|---|---|
| Discovery | Async TCP pre-filter, HTTP/HTTPS (TLS 1.0+), redirects pinned to the same host and scanned ports. By default up to 10 extra GETs per endpoint: a catch-all/SPA guard, PHP-only application paths proven by **content**, same-host `.php` links (`--no-deep` turns this off). |
| Version triage | Fixed releases from `advisory.json`; distribution-aware (frozen versions, backport hints only for branches a distribution ships). |
| Exposed FastCGI | Two benign records (`FCGI_GET_VALUES`, a request for a script that does not exist) on ports that do not speak HTTP → `FPM_EXPOSED`. |
| `--oracle` (opt-in) | Up to 2 ~400-byte multipart POSTs per endpoint. Pre-fix PHP prints a session-write warning the fix removed, so the result describes the **running** process — including distribution backports and workers never restarted. Answers only when the server displays PHP warnings; silence is never "patched". |
| Host verification | Read-only, over SSH (`--verify`) or on the host (`--local`, Linux; `--windows-collector`, Windows/IIS): every PHP build incl. cPanel / Plesk / DirectAdmin / LiteSpeed / containers, package changelogs, replaced binaries still running, interim-mitigation state per SAPI and FPM pool. |
| `--ioc` (opt-in) | Read-only compromise indicators: changed PHP files (mtime + ctime, SHA-256), webshell patterns, PHP in session/tmp files, shells spawned by PHP workers. No file content leaves the host. |
| Closure & SLA | Per-asset closure state, due dates (`--sla`, owner from the `owner=` label), weekly diff incl. closure changes. |
| Reports & exports | HTML, XLSX, DOCX, CSV, JSON (English or Turkish), `findings.json` (schema: `docs/findings.schema.json`), Nessus v2 XML, SARIF 2.1.0, DefectDojo. NVD CVSS 3.1 where official. |
| Evidence | `--evidence-pack [--sign-key]`: one zip with a SHA-256 manifest, optionally signed with `ssh-keygen -Y sign`; `--verify-pack` checks it. |
| Second opinion | `--targets-from` nuclei JSONL / Shodan JSON: scanned and verified like any target; disagreements are listed. |
| Agents | `--mcp`: stdio MCP server (plan / scan / findings / verify_pack); the scope cannot be dropped. Contract: `SKILL.md`. |
| New advisories | Data only: `--advisory file.json`, validated with `--check-advisory` (`docs/ADVISORY.md`). |

## Safety model

- `--scope` is required; one out-of-scope target aborts the run before any traffic (`--no-scope` is an explicit,
  recorded waiver). SSH targets are scope-checked too.
- Hostnames are resolved once and pinned; the resolved IP must be inside the approved ranges (`--scope-trust-names` for
  an owner-approved CDN name).
- Every connection is rate limited (`--rate`, `--per-host`); `--list` shows the worst-case duration first.
- Text from targets is escaped in HTML and neutralised against formula injection in XLSX / CSV / DOCX.
- Secrets are taken from environment variables where possible and redacted from the evidence pack's command line.

## Benchmark

[`docs/BENCHMARK.md`](docs/BENCHMARK.md): 14 isolated targets with known ground truth, 8 public scanners and nuclei
templates. php2shell-scanner in its default mode and with `--oracle`: **0 misses, 0 false alarms**. Every banner-only
tool raised false alarms on Ubuntu's backported 8.3.6, and only this tool identified an exposed PHP-FPM socket. The
document also lists this tool's trade-offs (a high "verify" ratio is the price of not trusting banners).

## Measured

| Scenario | Result |
|---|---|
| 1,020 hosts × 10 ports (local mocks, rate 3000/s) | 33–37 s end to end |
| /16 report generation (262k endpoints, 31k live assets) | 26 s, ~225 MB peak RSS |
| Docker lab (`tests/oracle_lab.py --full`): 7.4 and 8.1–8.5 pre-fix/fixed, FPM, Ubuntu backport, silent configs, phpredis, link discovery, exposed FPM, in-place upgrade | 30/30 |
| Host lab (`tests/host_lab.py`): Ubuntu 24.04 Apache/mod_php, `--local --ioc` in the container | 15/15 |
| Real PHP 8.3.6 (Ubuntu 24.04) + real sshd (`tests/e2e_real_php.py`) | all checks pass |

## Documentation

- [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) — the full guide (also `php2shell.pyz --guide`)
- [`docs/FIRST_ENGAGEMENT.md`](docs/FIRST_ENGAGEMENT.md) — runbook for a first authorized assessment (`--profile pilot`)
- [`docs/ADVISORY.md`](docs/ADVISORY.md) — writing an advisory for the next PHP vulnerability
- [`docs/BENCHMARK.md`](docs/BENCHMARK.md) — comparative measurement
- [`docs/findings.schema.json`](docs/findings.schema.json) — `findings.json` schema
- [`SKILL.md`](SKILL.md) — contract for AI agents using the MCP server

## Development

```
python3 -m unittest tests.test_p2s     # unit tests
python3 tests/integration_test.py      # rate limit, TLS 1.0, scope, redirects, resume, exports, MCP (local mocks)
sudo python3 tests/e2e_real_php.py     # real PHP + real sshd, disposable machine / CI only
python3 tests/oracle_lab.py --full     # --oracle against real PHP builds (Docker)
python3 tests/host_lab.py              # --local / --ioc / mitigation / closure on real Ubuntu hosts (Docker)
BENCH_TOOLS=<clones> python3 tests/benchmark.py   # isolated comparison with public scanners
sh build.sh                            # tests, then php2shell.pyz and docs/USER_GUIDE.md from p2s/
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security issues: [`SECURITY.md`](SECURITY.md).

## References

- [PHP 8 changelog](https://www.php.net/ChangeLog-8.php) · NVD
  [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618) /
  [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)
- [Rapid7](https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/) ·
  [Sansec](https://sansec.io/research/php2shell) ·
  [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)

## License

MIT — see [`LICENSE`](LICENSE).
