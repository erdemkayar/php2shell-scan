# PHP2Shell scanners — comparative measurement

Date: 2026-10-23 · measured with php2shell-scanner 2.9 (detection logic unchanged in 3.0) · Reproduce: `BENCH_TOOLS=<clones> python3 tests/benchmark.py`
Raw results: `docs/benchmark-results.json`.

## Method

- **Targets:** 14 Docker targets with known ground truth — **V** vulnerable, **P** patched, **N** no PHP — built from real
  PHP: upstream php:7.4 / 8.5.11 / 8.5.12 images and Ubuntu 24.04's own packages `8.3.6-0maysync1` (pre-fix) and
  `8.3.6-0ubuntu0.24.04.13` (backported fix).
- **Isolation:** targets and tools share an `--internal` Docker network with no route to the internet or the local
  network; every run checks that, and aborts if the runner can reach the internet.
- **Third-party code:** read before use, mounted read-only, run in a throw-away `python:3.12-slim` container.
- **Scoring:** every tool's output is normalised to VULN / PATCHED / UNKNOWN ("verify") / NONE (no PHP signal).
  A vulnerable target reported PATCHED or NONE is a **MISS** (the dangerous error); a patched target reported VULN is a
  **FALSE ALARM**.

### Tool versions and exclusions

| Tool | Commit | How it was run |
|---|---|---|
| php2shell-scanner | this repository | `--no-deep` (passive only), default (discovery on), `--oracle` |
| zarguell/php2shell-scanner | 98d7aa5 | defaults (oracle on); `--prove-rce`, `--cdp`, `--local` not used |
| CyberRoute/php2shell-scanner | 7f02e61 | `--target … --yes` |
| mohamedation/php2shell-scanner | 6a59afa | `--target … --yes`; `--lfi` (exploitation path) not used |
| bladehstream/php2shell_detect | a305784 | `php_cve_scanner.py --target … --port` (`--fpm-port 9000` on the FPM target) |
| JoasASantos/php2shell-scanner | 5394f44 | URL target; `--probe` (load probe) and `--recon` not used |
| Ademking nuclei templates | 1840a13 | `CVE-2026-109618/109619.yaml` only; injection / LFI templates not used |
| ProjectDiscovery nuclei template | `main`, sha256 503bf9ee… | `CVE-2026-109618.yaml` (nuclei v3.4.10); tagged intrusive: it sends OOM-triggering payloads |
| 0xrsydn/php2shell-scan | 2e23e08 | **not run**: its method relies on terminating PHP workers (~41 MB multipart corpus per host), and the repository also includes exploitation tooling |
| pentestershell, devploit | — | not run: exploitation / research kits |

## Summary

| Tool | Hit | Verify | **Miss** | **False alarm** | Correct (patched / no PHP) |
|---|---|---|---|---|---|
| php2shell-scanner `--no-deep` (passive) | 3 | 5 | 3 | 0 | 3 |
| **php2shell-scanner (default: discovery on)** | 4 | 8 | 0 | 0 | 2 |
| **php2shell-scanner `--oracle`** | 6 | 5 | 0 | 0 | 3 |
| zarguell/php2shell-scanner | 6 | 0 | 3 | 2 | 3 |
| CyberRoute/php2shell-scanner | 5 | 5 | 1 | 2 | 1 |
| mohamedation/php2shell-scanner | 5 | 0 | 4 | 2 | 3 |
| bladehstream/php2shell_detect | 5 | 1 | 3 | 2 | 3 |
| JoasASantos/php2shell-scanner | 5 | 1 | 3 | 2 | 3 |
| nuclei: Ademking templates | 5 | 0 | 4 | 3 | 2 |
| nuclei: ProjectDiscovery (intrusive) | 5 | 0 | 4 | 2 | 3 |

## Per target

| Target (truth) | p2s passive | p2s default | p2s --oracle | zarguell | CyberRoute | mohamedation | bladehstream | JoasASantos | nuclei/Ademking | nuclei/PD |
|---|---|---|---|---|---|---|---|---|---|---|
| up-8.5.11 (V) | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln |
| up-8.5.12 (P) | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✘ FALSE ALARM | ✔ (no PHP seen) |
| up-8.5.11-quiet (V) | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln |
| up-8.5.11-hidden (V) | ✘ MISS | ? verify | ? verify | ✘ MISS | ? verify | ✘ MISS | ✘ MISS | ✘ MISS | ✘ MISS | ✘ MISS |
| ubuntu-old-prod (V) | ✘ MISS | ? verify | ? verify | ✘ MISS | ? verify | ✘ MISS | ✘ MISS | ✘ MISS | ✘ MISS | ✘ MISS |
| ubuntu-new-prod (P) | ✔ (no PHP seen) | ? verify | ? verify | ✔ (no PHP seen) | ? verify | ✔ (no PHP seen) | ✔ (no PHP seen) | ✔ (no PHP seen) | ✔ (no PHP seen) | ✔ (no PHP seen) |
| ubuntu-old-banner (V) | ? verify | ? verify | ? verify | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln |
| ubuntu-new-banner (P) | ? verify | ? verify | ? verify | ✘ FALSE ALARM | ✘ FALSE ALARM | ✘ FALSE ALARM | ✘ FALSE ALARM | ✘ FALSE ALARM | ✘ FALSE ALARM | ✘ FALSE ALARM |
| ubuntu-old-show (V) | ? verify | ? verify | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln |
| ubuntu-new-show (P) | ? verify | ? verify | ✔ | ✘ FALSE ALARM | ✘ FALSE ALARM | ✘ FALSE ALARM | ✘ FALSE ALARM | ✘ FALSE ALARM | ✘ FALSE ALARM | ✘ FALSE ALARM |
| eol-7.4-show (V) | ? verify | ? verify | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln | ✔ vuln |
| static-front (V) | ✘ MISS | ✔ vuln | ✔ vuln | ✔ vuln | ? verify | ✘ MISS | ✘ MISS | ? verify | ✘ MISS | ✘ MISS |
| no-php (N) | ✔ | ✔ | ✔ | ✔ | ? verify | ✔ | ✔ | ✔ | ✔ | ✔ |
| fpm-9000 (V) | ✔ vuln | ✔ vuln | ✔ vuln | ✘ MISS | ✘ MISS | ✘ MISS | ? verify | ✘ MISS | ✘ MISS | ✘ MISS |

Targets: **up-\*** official php Docker images; **-quiet** `display_errors=0`; **-hidden** also `expose_php=0`;
**ubuntu-\*-prod** the distribution's production php.ini (expose_php, display_errors, display_startup_errors off);
**-banner** `expose_php=1`; **-show** banner and warnings on; **static-front** static front page, pre-fix PHP behind a
link; **fpm-9000** PHP-FPM socket reachable from the network.

## Observations

1. **Every banner-only tool raises false alarms on the Ubuntu backport**, because the patched `8.3.6-0ubuntu0.24.04.13`
   shows the same `PHP/8.3.6` banner as the unpatched package. php2shell-scanner says "patched" from behaviour when
   warnings are visible and otherwise "verify", leaving the decision to host verification (`--verify` / `--local`).
2. **The Ademking template also flags patched upstream 8.5.12.** Its matcher accepts two warnings that fixed builds also
   print and does not require the distinguishing third one — predicted from reading the template, confirmed here.
3. **Only php2shell-scanner identifies the exposed PHP-FPM socket**; bladehstream sees the open port but does not speak
   FastCGI.
4. **PHP behind a link on a static front page** is found by zarguell's spider and by php2shell-scanner's link
   harvesting; the other tools miss it.
5. **php2shell-scanner's own trade-offs:**
   - Passive-only mode (`--no-deep`) misses hosts that disclose nothing and the static front page. That is why
     discovery (GET only) is the default since 2.9: misses went from 3 to 0, and those hosts land in "verify".
     `--oracle`, where authorized, turns some of them into definitive verdicts.
   - The "verify" ratio is high (8 of 14 by default, 5 with `--oracle`): the price of not treating a banner as proof.
     Definitive answers come from host verification, measured separately in `tests/host_lab.py`.
   - The measurement surfaced a precision bug, fixed before these numbers: official php Docker images report Apache
     "(Debian)", which made PHP 8.5.11 a "verify" item although Debian never packaged PHP 8.5. A distribution hint now
     counts only for branches that distribution ships (`distro_branches` in `advisory.json`).
6. **Network footprint:** the ProjectDiscovery template sends multi-MiB OOM payloads to every target;
   php2shell-scanner sends no exploit, crash or load traffic.

## Limitations

- The targets were designed by the authors of this tool. The scenarios come from the field (distribution backports,
  hidden banners, static front pages, exposed FPM), but selection bias is possible, and there are only 14.
- Other tools ran at pinned commits; newer versions may behave differently.
- Host-side capabilities (SSH / `--local`, `--ioc`, closure) are not in this table, which is remote-only; they are
  measured in `tests/host_lab.py`.

## Commercial scanners (published documentation only, not run)

- **Tenable:** local (credentialed) checks for distribution packages and a version-based remote check
  ([Tenable FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote),
  e.g. [plugin 369972](https://www.tenable.com/plugins/nessus/369972)).
- **Qualys:** QID 389102 general check, QID 39033 unauthenticated check
  ([Qualys blog](https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities)).
- **Rapid7:** `php-cve-2026-109618` and the Ubuntu-specific `ubuntu-cve-2026-109618`
  ([InsightVM docs](https://docs.rapid7.com/insightvm/php2shell/)).

Credentialed package checks in these products cover distribution backports. Their published documentation does not
describe verifying the running process (restart state), a behavioural check, exposed FastCGI, compromise indicators,
or remediation closure / evidence packs.
