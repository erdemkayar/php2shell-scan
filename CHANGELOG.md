# Changelog

## 3.0.0 — first public release

- English CLI, user guide and documentation; reports in English (default) or Turkish (`--lang tr`).
- Discovery on by default (GET only; `--no-deep` to disable): catch-all/SPA guard, PHP-only application paths proven
  by content, same-host `.php` links.
- `--oracle`: opt-in behavioural check of the running PHP (PHP 7.x and 8.x wording), session-name learning, link-aware
  path selection; bound to the PHP2Shell advisory.
- Exposed PHP-FPM / FastCGI detection (`FPM_EXPOSED`); port 9000 in the default port list.
- Host verification: interim-mitigation state per SAPI and FPM pool, `--local` / `--import-local` for hosts without SSH,
  a read-only PowerShell collector for Windows/IIS (`--windows-collector`), opt-in compromise indicators (`--ioc`).
- Per-asset remediation closure, SLA deadlines (`--sla`, `owner=` label), closure changes in the weekly diff.
- Exports: `findings.json` (with JSON Schema), Nessus v2 XML, SARIF 2.1.0, DefectDojo; NVD CVSS 3.1 vectors.
- `--evidence-pack` with SHA-256 manifest and optional OpenSSH signature; `--verify-pack`.
- `--targets-from` nuclei / Shodan input with a disagreement report; `--mcp` server for agents (`SKILL.md`).
- Advisory engine: `--check-advisory`, `docs/ADVISORY.md`; distribution hints limited to branches a distribution ships.
- `--profile pilot` and `docs/FIRST_ENGAGEMENT.md`.
- Tests: Docker labs with real PHP builds (`tests/oracle_lab.py`, `tests/host_lab.py`), isolated comparative benchmark
  (`tests/benchmark.py`, `docs/BENCHMARK.md`).
