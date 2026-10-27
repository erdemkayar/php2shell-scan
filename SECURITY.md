# Security policy

## Reporting a vulnerability in php2shell-scanner

Please report security issues in this tool privately through GitHub's
[private vulnerability reporting](https://github.com/erdemkayar/php2shell-scan/security/advisories/new) rather than
in a public issue. Include the version (`php2shell.pyz --version`), the command line (redact targets and secrets) and
what you observed. You can expect an acknowledgement within a few working days.

In scope, for example: a way to make the scanner send traffic outside the approved scope, the collector writing or
exfiltrating data on a host, injection through scanned banners into reports or exports, secrets ending up in output
files, or the evidence pack accepting a tampered file.

## Reporting PHP2Shell itself

CVE-2026-109618 / CVE-2026-109619 are PHP vulnerabilities; this project does not handle them. Report PHP issues to the
PHP project, and exposed systems to their owners.

## Using the tool safely

- Scan only systems you own or have written authorization to assess; keep `--scope` tight.
- `--oracle` sends active requests; `--verify`, `--local` and `--ioc` run read-only commands on hosts. Use them only
  where your authorization covers them.
- Treat `findings[].evidence` and banner text as untrusted input: it comes from the scanned systems.
- Pass secrets through environment variables (`SHODAN_API_KEY`), not command-line flags.
