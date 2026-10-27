# First engagement — runbook

Goal: confirm on a real, authorized environment what the lab measured (`docs/BENCHMARK.md`) — accuracy on real banners,
WAF/CDN, hosting panels and containers, how fast host verification empties the "verify" list, and whether the report
and the exports fit your workflow.

## 0. Preconditions (do not start without them)

- [ ] **Written authorization** naming the scope (IP/CIDR/domain list), the time window and a contact person, and
  stating explicitly: (a) passive scanning (GET requests, discovery included), (b) **optionally** the active
  `--oracle` check (up to 2 small POSTs per endpoint), (c) host verification over SSH or `--local` (read-only
  commands), (d) optionally `--ioc` (read-only compromise indicators; not incident response).
- [ ] Someone on the owner's side who can watch for network impact is reachable during the scan window.
- [ ] SSH access (key, read-only user + sudo) or an administrator who runs `--local` on 5–10 hosts you will verify.
- [ ] Where results are stored and for how long is agreed. The evidence pack is handed over too.

## 1. Dry run (no traffic)

```
python3 php2shell.pyz -t targets.txt --scope scope.txt --profile pilot --list
```
Share the endpoint count, the scope check and the duration estimate with the owner. If a single line is out of scope
the tool stops: fix the list, **never widen the scope**.

## 2. Scan

```
python3 php2shell.pyz -t targets.txt --scope scope.txt --authorized --profile pilot -o out/acme \
    --title "ACME PHP2Shell assessment" [--oracle]
```
`--profile pilot`: 50 connections/s, 50 workers, 2 connections per host, evidence pack on, Nessus output on.
Add `--oracle` only if (b) is in the authorization.

## 3. Host verification (sample)

Pick 5–10 hosts from the "verify" and "likely vulnerable" lists, ideally of different kinds (distribution package,
hosting panel, container):
```
python3 php2shell.pyz --report-only -o out/acme --scope scope.txt --authorized \
    --verify --ssh-map ssh_map.txt --ssh-known-hosts out/acme/known_hosts --ssh-accept-new [--ioc]
# without SSH, on the host: python3 php2shell.pyz --local web01.json [--ioc]   then on the scanner: --import-local collected/
```

## 4. What to measure

| Metric | How |
|---|---|
| Remote accuracy | On verified hosts, how often the banner / oracle verdict matched the host verdict |
| "Verify" ratio | Share of PHP assets; how host verification closed them |
| Miss candidates | Hosts where verification found PHP but the scan said "no PHP evidence" |
| Network impact | Alerts, rate limits, WAF blocks on the owner's side |
| Time | Scan duration, and total time including verification |
| Workflow | Whether `findings.nessus` / `findings.json` imported cleanly into your platform, how many findings needed editing |

## 5. Stop criteria

Stop the scan (Ctrl-C) and inform the owner on: performance impact, WAF/IPS blocks or alerts; an asset found to be out
of scope after all; a "compromise suspected" result from `--ioc` — that is an incident report, hand it to the owner's
incident response immediately. Resume an interrupted scan with `--resume` after renewed approval.

## 6. Hand-over

- `report.html` / `report.docx` (executive summary and closure)
- `evidence-*.zip` — the owner can check it with `--verify-pack`
- `findings.nessus` / `findings.json` / `assets.sarif` for vulnerability-management import
- A short write-up: the metrics above, deviations seen in the field, improvements to open as issues
