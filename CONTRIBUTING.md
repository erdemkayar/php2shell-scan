# Contributing

Thanks for helping. A few principles keep this tool trustworthy on other people's networks:

1. **Safe by default.** No exploit, crash or load traffic. Anything active stays opt-in, documented in the report's
   method section, and rate limited. Nothing may bypass the scope check.
2. **Evidence over guesses.** A new verdict needs a reproducible test against real software (see `tests/oracle_lab.py`
   and `tests/host_lab.py`), not only a mock. Silence is never "patched".
3. **No new mandatory dependencies.** The package runs on a stock Python 3.9+; optional extras must degrade gracefully.
4. **Data, not code, for new advisories.** Fixed versions and texts belong in an advisory file (`docs/ADVISORY.md`).

## Workflow

```
python3 -m unittest tests.test_p2s
python3 tests/integration_test.py
python3 tests/oracle_lab.py --full     # Docker; when touching discovery, the oracle or classification
python3 tests/host_lab.py              # Docker; when touching the collector, mitigation, IoC or closure
sh build.sh
```

- Keep changes focused; describe the behaviour change and how you verified it in the pull request.
- Update `p2s/guide.md` (it is the source of `docs/USER_GUIDE.md` and `--guide`) and `CHANGELOG.md` for user-visible
  changes.
- Report-facing text exists in English and Turkish (`p2s/report.py`, `p2s/classify.py`, `p2s/export.py`); add both.

Security issues: see [`SECURITY.md`](SECURITY.md) — please do not open public issues for them.
