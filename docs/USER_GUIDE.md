# php2shell-scanner — User Guide

Exposure triage, host verification and remediation tracking for CVE-2026-109618 / CVE-2026-109619 (PHP2Shell, PHP core
remote code execution, fixed on 2026-10-21). One file: `php2shell.pyz`. Print this guide with `php2shell.pyz --guide`.

## 1. What it does and does not do

Does:
- Finds web services on the IPs / CIDRs / hosts you give it (TCP pre-filter, then HTTP/HTTPS).
- Detects PHP and its version from response headers (X-Powered-By, Server, PHPSESSID, CMS markers) and from discovery
  requests (section 5).
- Compares the version with the fixed releases in the advisory and tells distribution builds (Ubuntu / Debian / RHEL),
  which patch without changing the version number, apart from upstream builds.
- Finds PHP-FPM / FastCGI sockets reachable from the network (section 6b).
- Optionally (`--oracle`) checks the **running** PHP by its behaviour: works with a hidden version, on a distribution
  backport and on workers that were never restarted (section 6a).
- Verifies hosts read-only over SSH or with a local collector: definitive vulnerable / patched / restart required,
  interim-mitigation state and, optionally, compromise indicators (section 7).
- Tracks remediation per asset (closure, SLA) and writes HTML, Excel, Word, CSV, JSON, Nessus, SARIF and DefectDojo
  reports, with a diff against last week's run.

Does not:
- Send exploit, memory-exhaustion or crash traffic. By default it sends GET requests only; the only active request is the
  small multipart POST of `--oracle`, sent only when you ask for it.
- Call anything "verified vulnerable" without host evidence; banner results are always triage.
- Send a single packet to a target outside the approved scope. `--scope` is mandatory; running without one requires an
  explicit `--no-scope`, and the report then says the scope was not enforced.

## 2. Requirements

- Python 3.9 or later. Nothing else is required.
- Optional: `openpyxl` (Excel), `python-docx` (Word), `cryptography` (TLS certificate names). Without them those outputs
  are skipped; HTML / CSV / JSON are always written. `python3 -m pip install --user openpyxl python-docx cryptography`
- Host verification over SSH: an `ssh` client and key-based access.

## 3. Quick start

```
# 1. write a target file and a scope file (section 4)
# 2. dry run: how many endpoints, how long, does the scope hold (no traffic)
python3 php2shell.pyz -t targets.txt --scope scope.txt --list

# 3. scan
python3 php2shell.pyz -t targets.txt --scope scope.txt --authorized -o out/acme-2026w43 --title "ACME - PHP2Shell"

# 4. open out/acme-2026w43/report.html (or report.xlsx / report.docx)
```

`--authorized` is required on every scan: it states that you are authorized to assess every target.
For a first engagement, `--profile pilot` sets gentle rates and turns on the evidence pack and Nessus output (flags you
pass explicitly still win); see `docs/FIRST_ENGAGEMENT.md`.

## 4. Target and scope files

Target file — one target per line, `#` starts a comment, labels are free-form:

```
203.0.113.0/24          customer=ACME env=prod owner=ops@acme.example
198.51.100.10           customer=ACME env=prod sni=portal.acme.example ports=443,8443
shop.acme.example:8443  customer=ACME
https://intranet.acme.example/app
```

Special keys: `ports=` (ports for this line), `sni=` (TLS SNI and Host header; needed when several sites share an IP or
the server rejects handshakes without SNI), `path=` (start path). Every other `key=value` pair is a label; `customer`
drives the group table (change with `--group-by`), `owner` is used for the SLA (section 8).

Scope file — the ranges the system owner approved:

```
203.0.113.0/24
198.51.100.10
portal.acme.example
*.acme.example
```

If even one target is outside the scope, nothing is sent and the out-of-scope hosts are listed. `--exclude` skips
specific in-scope IPs (lines may carry a trailing comment: `10.0.0.1  prod-db  # do not touch`). An invalid line stops
the run before it starts.

Hostnames are resolved once and pinned: the scope check, the TCP probe and every HTTP request go to the same checked IP
(SNI / Host carry the name). Rules:
- If the scope has IP ranges, the resolved IP must be in one of them, even when the name itself is approved.
- A name approved but resolving elsewhere (CDN, SaaS) stops the run: add that IP to the scope, or pass
  `--scope-trust-names` if the owner approved the name.
- With a names-only scope, a name match is enough.
- Unresolvable names are skipped and reported as a COVERAGE GAP.
- `-4` / `--ipv4-only`: scan only the IPv4 addresses of names (avoids timeouts on networks without IPv6).
- DNS answers are stored in `dns.json`; `--resume` reuses them (empty answers are asked again).

## 5. Scan settings and large networks

| Setting | Default | Notes |
|---|---|---|
| `--rate` | 300/s | All connections count (TCP, HTTP/HTTPS attempts, redirects, discovery). Start with 50–300 on a production network. |
| `--concurrency` | 400 | Concurrent workers. |
| `--per-host` | 4 | Concurrent connections per host. |
| `--retries` | 1 | Retries on timeout/transport errors. Protocol rejections are not retried. |
| `--ports` | 80,443,8080,8443,9000 | 80/8080 HTTP, 443/8443 HTTPS; other ports try HTTP, then HTTPS. Open ports that do not speak HTTP (e.g. 9000) get the FastCGI / PHP-FPM check (section 6b). |
| `--no-deep` | (discovery on) | By default up to 10 more GETs per endpoint; `--no-deep` turns that off. Discovery: a random `/p2s-xxxx.php` (recognises catch-all / SPA servers that answer 200 for every path), `/index.php`, paths of PHP-only applications (WordPress, Nextcloud, phpMyAdmin, Joomla, Drupal — a **content match** is required, a status code alone never counts) and up to 2 same-host `.php` links from the page. |
| `--oracle` | off | ACTIVE behavioural check: up to 2 small multipart POSTs per endpoint (section 6a). Rate limited like everything else. |

- Always run `--list` first: it prints the endpoint count and the worst-case duration.
- Scans above 20,000 endpoints need `--yes`. A single CIDR above `--max-hosts` (65,536) is skipped and reported as a
  coverage gap.
- Redirects are followed only to the same (pinned) host and to scanned ports; other redirects are noted, not followed.
  If a later hop fails, the first response's banner is kept.
- Measured in the lab: 1,020 hosts × 10 ports in 33 s; for a /16 (262k endpoints, 31k live assets) report generation
  takes 27 s and ~235 MB. On real networks latency and `--rate` decide the duration.
- Servers that only speak TLS 1.0/1.1 are scanned too (common on end-of-life PHP).

## 6. Statuses

| Status | Meaning | Action |
|---|---|---|
| FPM_EXPOSED | PHP-FPM / FastCGI reachable from the network (6b) | Close the port now; remote code execution regardless of patch level |
| VERIFIED_VULNERABLE | Verified on the host: unpatched PHP | Upgrade, restart workers |
| ORACLE_VULNERABLE | `--oracle`: the running PHP answered like a pre-fix build | Upgrade, restart workers |
| VERIFIED_RESTART_REQUIRED | Patched on disk, the running process still uses the old binary | Restart PHP-FPM / Apache (mod_php: full stop/start) |
| LIKELY_VULNERABLE | Banner: version below the fixed release, no distribution hint | Verify on the host, upgrade |
| EOL_NO_UPSTREAM_FIX | PHP 8.1 or older, no distribution hint | Move to a supported branch |
| VERIFY_DISTRO_BACKPORT | Distribution build; the fix may be backported without a version change | Verify on the host (package changelog) |
| PHP_VERSION_HIDDEN | PHP present, version hidden | Verify on the host; treat as exposed until proven patched |
| PATCHED_BY_BANNER | The banner version is a fixed release | None |
| ORACLE_PATCHED | `--oracle`: the running PHP answered like a fixed build | No patch action; stop displaying PHP warnings to clients |
| VERIFIED_PATCHED | Verified on the host: patched (version or backport) | None |
| NO_WEB_RESPONSE | Port open, no HTTP(S) answer — not assessed | Add SNI or verify on the host |
| NO_PHP_INDICATOR | No PHP evidence in the responses (not proof of absence) | None |
| VERIFIED_NO_PHP | No PHP on the host | None |

The first eight statuses need action and make the exit code 2.

Frozen distribution versions such as 8.3.6 / 8.1.2 count as "verify" even without a distribution hint in the banner,
so they are never called patched by mistake, and genuinely unpatched installs with the same number (e.g. a Docker
image) still go to host verification. ppa:ondrej (sury) and Remi ship upstream version numbers, so those are judged by
the number. Ubuntu 24.04 shipped the fix as `8.3.6-0ubuntu0.24.04.13` while the banner still says `PHP/8.3.6`
(observed in the real package changelog on 2026-10-22). A Server header naming a distribution only counts as a backport
hint for PHP branches that distribution actually ships (`distro_branches` in `advisory.json`): the official php Docker
images report Apache "(Debian)" with PHP 8.5, which Debian never shipped.

## 6a. Behavioural check (`--oracle`)

`--oracle` sends an **active request**: to every endpoint that answers HTTP, first to the endpoint's own path (or a
same-host `.php` link when the front page is static), then to `/index.php`, at most two ~400-byte multipart POSTs. The
request carries an invalid session id (`PHPSESSID=_` plus the session cookie name seen on the endpoint), a
`PHP_SESSION_UPLOAD_PROGRESS` field and a one-byte file. It is not an exploit, puts no memory pressure on the server and
writes no session file. Your authorization must still cover active requests; the report's method section says the check
was used.

How it decides: PHP prints session warnings during "PHP Request Startup" for this request. A pre-fix build prints three;
a fixed build does not print "Failed to write session data" (the fix removed that path).

| Answer | Result |
|---|---|
| 3/3 warnings | `ORACLE_VULNERABLE`, whatever the banner says (the running process decides) |
| 2/3 warnings (files handler) | `ORACLE_PATCHED` for a hidden version, a distribution build or a fixed banner. If the banner shows a vulnerable upstream version, the banner status is kept and the note says "Conflict" |
| 0/3 (silent) or partial | No verdict; the banner status is kept. Silence does NOT mean patched |

Validated in the lab (`tests/oracle_lab.py`):
- 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11 and EOL 8.1 → 3/3; 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 → 2/3 (mod_php and FPM + nginx).
- PHP 7.4 (EOL) → 3/3, but only when warnings are shown explicitly: PHP 7 defaults `display_startup_errors` to Off (8.0
  turned it On), so a php.ini-less 7.x image stays silent. The first warning is worded differently on 7.x; both are
  recognised.
- On a site with a static front page the oracle follows the same-host `.php` link (lab: `/portal/search.php` → 3/3).
- **Ubuntu 24.04:** `8.3.6-0maysync1` (pre-fix) 3/3, `8.3.6-0ubuntu0.24.04.13` (backport) 2/3. Both report "8.3.6": the
  oracle settles `VERIFY_DISTRO_BACKPORT` without SSH.
- **Workers not restarted:** the package upgraded to the backport while Apache runs → still 3/3, also after
  `apachectl graceful` and `-k restart` (the parent keeps the deleted libphp); only a stop/start gives 2/3.

When it stays silent (no verdict):
- The server does not display PHP warnings: both `display_errors` **and** `display_startup_errors` must be on.
  Distribution production php.ini files (Ubuntu / Debian / RHEL) turn them off; php.ini-less official Docker images and
  development settings turn them on. In practice the oracle answers mostly on containers, development/test hosts and
  misconfigured servers.
- `session.upload_progress.enabled=0`, `session.use_strict_mode=1`, E_WARNING removed from `error_reporting`, a session
  handler other than `files` (e.g. phpredis), or the request never reaching PHP (static site, WAF).

A server that gives an `ORACLE_*` answer displays PHP warnings to clients: that is information disclosure on its own and
should be turned off. If the host check says "patched" while the oracle finds `ORACLE_VULNERABLE`, the status is kept
and the note names the conflict (workers not restarted, or another PHP serves that port).
`--oracle` is bound to the PHP2Shell advisory and refused with any other advisory.

## 6b. Exposed PHP-FPM / FastCGI

On an open port that does not speak HTTP the scanner sends two benign FastCGI records: `FCGI_GET_VALUES` (a management
record) and a request for a script that **does not exist** (`/p2s-<random>.php`). Nothing runs; no `PHP_VALUE` /
`PHP_ADMIN_VALUE` is sent. PHP-FPM answers "File not found" with `X-Powered-By: PHP/x.y.z`. The result is
`FPM_EXPOSED`: a FastCGI socket reachable from the network is a direct remote-code-execution path regardless of the
PHP2Shell patch, and it is reported first. That is why 9000 is a default port. Validated against php:8.5.11-fpm.

## 7. Host verification over SSH

```
python3 php2shell.pyz -t targets.txt --scope scope.txt --authorized -o out/acme \
    --verify --ssh-map ssh_map.txt --ssh-known-hosts out/acme/known_hosts --ssh-accept-new
```

`ssh_map.txt`:
```
203.0.113.10   audit@203.0.113.10   key=~/.ssh/id_ed25519
203.0.113.20   web-02                          # an ~/.ssh/config alias works too
10.0.0.5       admin@jump.acme.example port=2222
```

- `--verify`: actionable hosts; `--verify-all`: every host in the map. Both need `--authorized` and `--scope`; if a
  host or an IP-literal SSH target in the map is out of scope, no connection is made (aliases from ssh_config cannot be
  scope-checked and produce a warning).
- The collector creates and changes no files, but it does run commands: `-v` of every PHP binary found (`version` for
  FrankenPHP), package queries, a CVE search in package changelogs, whether running PHP processes use a binary replaced
  on disk (`/proc/<pid>/exe`), `apache2ctl -M`, and `docker exec <container> php -v` when Docker is present. These leave
  traces in system logs and the Docker event log: get the host owner's approval.
- Searched: /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin, /opt (cPanel ea-phpXX, Remi SCL, Plesk),
  /usr/local/lsws (LiteSpeed), /usr/local/phpXX (DirectAdmin) and running containers.
- A distribution changelog only vouches for that package's binaries: same branch, same version as the package, under
  /usr/bin or /usr/sbin. PHP in /usr/local, /opt or containers does not inherit it.
- FrankenPHP without a readable version, or mod_php that cannot be tied to a package, gives "manual review".
- If the host check contradicts the web banner (no PHP on the host but the web shows PHP; or the banner version is not
  found on the host) the banner status is kept and the note says "review". A failed SSH session also keeps the banner.
- One SSH session per host is capped at 300 s (5 s per `-v`). On hosts with many PHP builds (e.g. CloudLinux alt-php)
  more than 300 binaries / 200 containers / 500 processes make the result "manual review".
- **Interim-mitigation state:** the collector reads every php.ini set and its scan dir (conf.d / php.d), FPM pool
  `php_(admin_)value/flag` lines and Apache `php_flag` lines. For every web-facing SAPI (CLI excluded) it works out
  whether `session.upload_progress.enabled`, `file_uploads` or `enable_post_data_reading` is off. If all of them are, an
  unpatched host's closure becomes "open, interim mitigation active". A single FPM pool re-enabling them means no
  mitigation. `.user.ini` / `.htaccess` overrides are not read. A mitigation never replaces the patch.

### 7a. Hosts without SSH: `--local`

The same read-only collector runs on the host and the result travels as a file:
```
# on the host (root or sudo, Linux):
python3 php2shell.pyz --local web01.json [--ioc]
# on the scanner (a folder works too):
python3 php2shell.pyz -t targets.txt --scope scope.txt --authorized -o out/acme --import-local collected/
```
The file is matched to the scanned asset by the host's IP addresses; a file whose IPs are not in the approved scope is
not imported. Reports and closure work exactly as with SSH (`source: local`).

Windows / IIS: `--windows-collector p2s-collect.ps1` writes a read-only PowerShell collector. Run it on the host as
Administrator: `powershell -NoProfile -ExecutionPolicy Bypass -File p2s-collect.ps1 -Out web01.json [-Ioc]`, then import
the file with `--import-local`. It finds PHP builds (PATH, C:\php*, Program Files, XAMPP / WAMP / Laragon, Plesk, IIS
FastCGI applications), the php.ini mitigation state, IP addresses, binaries replaced while running and, with `-Ioc`,
changed PHP files in IIS site roots, webshell patterns and cmd / PowerShell processes started by w3wp / php-cgi. The CI
job `windows-collector` exercises it end to end on a real Windows runner with IIS + PHP FastCGI.

### 7b. Compromise indicators: `--ioc` (optional)

Used with `--verify`, `--verify-all` or `--local`. Read-only, and **no file content leaves the host**: only paths,
timestamps, sizes, SHA-256 and process lines are reported. Checks:
- `.php/.phtml/.phar/.user.ini/.htaccess` files changed after `--ioc-since` in web roots (Apache `DocumentRoot`, nginx
  `root`, /var/www, /srv/www, ~/public_html). Timestamps can be forged, so ctime is checked too. This list alone is not
  a finding (deployments change files as well).
- Webshell patterns in those files (`eval(base64_decode(...))`, `system($_GET...)` and similar).
- PHP code in session / tmp directories (`<?php` inside `sess_*`: the trace of an LFI → RCE chain).
- Shell or network tools spawned by a PHP worker (apache2 / httpd / php-fpm / lsphp / frankenphp).

The default `--ioc-since` is 30 days before the advisory was published. Without root (or password-less sudo), or when
the 500-file cap is hit, the check counts as incomplete and the asset cannot reach "closed and verified". An asset with
indicators enters the priority list as "compromise suspected" even if it is patched. This is not incident response; a
hit is where incident response starts. Your engagement must cover it.

## 8. Reports, closure and the weekly diff

Every asset has a **closure** state (a column and a summary in every report):

| Closure | Meaning |
|---|---|
| Compromise suspected | `--ioc` found indicators (independent of patch state, comes first) |
| Open | Needs action, no interim mitigation |
| Open, interim mitigation active | Unpatched, but upload progress / file uploads are off in every web SAPI |
| Patched, restart pending | Patched on disk, the running process is old |
| Closed (remote evidence only) | Banner or `--oracle` says patched, no host verification |
| Closed on host, IoC check pending | Patched on the host and the running process is patched; `--ioc` missing or incomplete |
| Closed and verified | Patched on the host + running the patched code + a complete, clean `--ioc` |
| No PHP evidence / not applicable | Out of the assessment |

The executive summary says "M of N PHP assets closed and verified"; the weekly diff also lists closure changes (e.g.
open → restart pending → closed and verified).

**Remediation deadlines (SLA):** every asset that needs action gets a due date. Defaults are critical 3, high 7,
medium 14 days; change them with e.g. `--sla critical=1,high=5`. Compromise suspected counts as critical. The first-seen
date is carried over from `--baseline`, so the clock does not restart every week. The owner comes from the `owner=`
label in the target file. The priority table shows the due date and the days overdue; the executive summary counts
overdue assets. A closed asset is stamped with `closed_on`.

In the `-o` folder:
- `report.html` — one self-contained file, filterable, printable (PDF). Tables are capped at the first 2,000 assets on
  very large scans.
- `report.xlsx` — summary + chart, priority, assets, endpoints, groups, changes, method.
- `report.docx` — executive report.
- `assets.csv`, `assets.json` (next week's baseline), `findings.json`, `results.jsonl` (raw results), `verify.json`,
  `passive.json`, `meta.json`.

Weekly run:
```
python3 php2shell.pyz -t targets.txt --scope scope.txt --authorized -o out/acme-w44 --baseline out/acme-w43/assets.json
```
Rebuild the reports without scanning (e.g. in Turkish): `python3 php2shell.pyz --report-only -o out/acme --lang tr`

## 8a. Exports, second opinion, evidence, agents

**Export formats** (`--formats`, default html,xlsx,docx,csv,json,findings):

| Format | File | Use |
|---|---|---|
| `findings` | findings.json | `php2shell.findings/1`: a stable schema for scripts and agents (`docs/findings.schema.json`) |
| `nessus` | findings.nessus | Nessus v2 XML: imports into most vulnerability-management and reporting platforms |
| `sarif` | assets.sarif | SARIF 2.1.0 dashboards |
| `defectdojo` | defectdojo.json | DefectDojo "Generic Findings Import" |

Only assets that need action become findings, one per kind per asset: vulnerability / verify, exposed PHP-FPM,
compromise indicators. Finding ids are stable across runs, so re-imports do not duplicate. Finding text follows
`--lang` (English or Turkish); the description stays abstract and concrete host data goes only to the evidence field.
CVE findings carry NVD's primary CVSS 3.1 (CVE-2026-109618: 9.8, -109619: 8.1; one finding covers both, so 9.8). No
vector is ever invented for an advisory that has none.

**Second opinion (`--targets-from`):** feed `nuclei -jsonl` or Shodan JSON lines as targets. They are scope-checked,
scanned and verified like any target; assets another tool flagged but this tool found patched or without PHP are listed
under "Disagreements with external tools" (e.g. a nuclei version match on an Ubuntu backport).

**Evidence pack (`--evidence-pack [--sign-key ~/.ssh/key]`):** raw results, host checks, reports, scope files, the
advisory used and the command line (secrets redacted) in one zip, with the SHA-256 of every file in `manifest.json`.
Signing uses OpenSSH (`ssh-keygen -Y sign`), no extra dependency. The auditor checks it with:
```
python3 php2shell.pyz --verify-pack evidence-20261023-101500.zip --allowed-signers allowed_signers --signer-identity auditor@example.org
```
A modified, missing or added file, or a bad signature, exits with 1.

**Agents (`--mcp`):** `python3 php2shell.pyz --mcp` starts a stdio MCP server with `php2shell_plan` (no traffic),
`php2shell_scan`, `php2shell_findings` and `php2shell_verify_pack`. A scan needs `authorized: true` and a scope; an agent
cannot drop the scope. Agent contract: `SKILL.md`.

## 9. Interruption and resume

Ctrl-C or a dropped connection: every result is written to `results.jsonl` as it arrives.
```
python3 php2shell.pyz <same arguments> --resume -o out/acme
```
An interrupted scan exits with 3 and every report shows an "INCOMPLETE SCAN" warning until `--resume` finishes it.
Endpoints that ended in an error are scanned again on resume.

## 10. A new advisory

Fixed releases and CVE ids live in the `advisory.json` built into the package. A new PHP advisory needs no code change:
write a file, check it with `python3 php2shell.pyz --check-advisory new.json`, use it with `--advisory new.json`.
Runbook: `docs/ADVISORY.md`. The report states which advisory it was assessed against.

## 11. Exit codes and automation

| Code | Meaning |
|---|---|
| 0 | Nothing needs action |
| 2 | Assets need action |
| 3 | Coverage incomplete: scan interrupted or targets skipped (DNS unresolved / `--max-hosts`) |
| 1 | Error, invalid argument / target, or out-of-scope target |

In cron / CI treat 2 and 3 separately: on 3 read the warning at the top of the report; re-run an interrupted scan with
`--resume`, fix the target list if targets were skipped. Reports built from a folder without completeness data (no
`meta.json`) show "COMPLETENESS UNKNOWN".

## 12. Limitations

- Banner results are triage. Reverse proxies and stripped headers hide the real version.
- `--oracle` only decides on servers that display PHP warnings; silence is not evidence (6a).
- The scope check runs at the start; if DNS changes later, the pinned IPs keep being used.
- "No PHP indicator" does not prove there is no PHP.
- PHP used only from the CLI (not web-facing) is outside the web scan.
- In host verification an old, non-web PHP CLI binary on the host also makes the result "vulnerable" (a conservative
  choice).
- Free-text notes in the reports are in English; labels and actions follow `--lang`.
- Shodan (`--shodan-key`) is third-party, possibly stale data and is used with low confidence.

## 13. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `NO_WEB_RESPONSE` with note `TLSV1_ALERT_INTERNAL_ERROR` | The server rejects handshakes without SNI: add `sni=<name>` to the target line. |
| `SSH failed: Host key verification failed` | The key in known_hosts differs. Use a per-engagement `--ssh-known-hosts`, `--ssh-accept-new` on first contact. |
| `SSH failed: Permission denied` | Wrong user / key in the ssh map. |
| No xlsx / docx | `openpyxl` / `python-docx` not installed (section 2). |
| Scan is slow | See the estimate with `--list`; dead IPs wait for timeouts. `--connect-timeout 2`, raise `--rate`. |
| Exit code 1, "outside the approved scope" | The target list and the scope disagree; check the listed hosts. |
| "the name is in scope but resolves to an IP outside the approved ranges" | The name resolves outside the approved ranges (CDN / SaaS). Add the IP to the scope, or `--scope-trust-names`. |
| "an approved scope is required" | Pass `--scope`; `--no-scope` to deliberately run without one. |

## 14. Tests and packaging (development)

```
python3 -m unittest tests.test_p2s          # unit tests
python3 tests/integration_test.py           # rate limit, TLS 1.0, scope, interrupt/resume, exports (local mocks)
sudo python3 tests/e2e_real_php.py          # real PHP + real sshd, disposable machine / CI only
python3 tests/oracle_lab.py [--full]        # --oracle against real PHP builds in Docker (--full: phpredis + restart)
python3 tests/host_lab.py                   # --local / --ioc / mitigation / closure on real Ubuntu hosts in Docker
BENCH_TOOLS=<clones> python3 tests/benchmark.py   # isolated comparison with public scanners (docs/BENCHMARK.md)
sh build.sh                                 # runs the unit tests and builds php2shell.pyz
```
CI: `.github/workflows/ci.yml` (Python 3.9 and 3.12, real-PHP end-to-end, Docker labs, Windows collector, package).
