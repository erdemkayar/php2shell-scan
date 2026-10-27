# Writing an advisory for a new PHP vulnerability

Every verdict comes from `p2s/advisory.json`. When a new PHP core vulnerability is published, no code change is needed:
write an advisory file, validate it, and pass it with `--advisory`.

## 1. Write the file

```json
{
  "id": "PHP-XXXX",
  "title": "short description",
  "cves": ["CVE-2027-000001"],
  "published": "2027-02-01",
  "fixed": {"8.3": "8.3.40", "8.4": "8.4.31", "8.5": "8.5.16"},
  "eol_below": "8.3",
  "distro_frozen_versions": {"8.3.6": "Ubuntu 24.04", "8.1.2": "Ubuntu 22.04"},
  "distro_branches": {"debian": ["7.4", "8.2", "8.4"], "ubuntu": ["7.4", "8.1", "8.3", "8.4", "8.5"]},
  "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "cvss3_score": 9.8,
  "sources": [["PHP release notes", "https://www.php.net/ChangeLog-8.php"]],
  "texts": {
    "en": {"vuln_title": "PHP-XXXX: ... ({cves})", "vuln_desc": "...", "vuln_impact": "...",
           "vuln_fix": "Upgrade PHP to {fixed} or later ...", "title": "PHP-XXXX exposure report", "sub": "CVE-2027-000001 - ..."},
    "tr": {"vuln_title": "PHP-XXXX: ... ({cves})", "title": "PHP-XXXX maruziyet raporu"}
  }
}
```

| Field | Required | Meaning |
|---|---|---|
| `id`, `cves`, `fixed` | yes | `fixed`: branch → first fixed release on that branch |
| `eol_below` | no | Versions below this branch are treated as having no upstream fix (default: the oldest `fixed` branch) |
| `published` | recommended | Default start date of `--ioc` (publication date − 30 days) |
| `distro_frozen_versions` | no | Versions distributions keep while backporting fixes: a banner showing one becomes "verify" |
| `distro_branches` | no | Which PHP branches each distribution family packages. A Server header naming the distribution is a backport hint only for these branches |
| `cvss3_vector`, `cvss3_score` | no | Only from an official source (NVD, the vendor). Importers compute severity from it. Never invent one |
| `texts` | no | Finding and report texts. Without it the PHP2Shell wording is used — **always set it for a new vulnerability** |
| `oracle` | **no** | Only `session-write`, and **only valid for PHP2Shell**. Do not set it in a new advisory: `--oracle` is then refused |

Host verification (SSH / `--local`) searches package changelogs for the ids in `cves`, so it needs no extra setting.
Check the package versions against the distribution's own advisory as well.

## 2. Validate

```
python3 php2shell.pyz --check-advisory php-xxxx.json
```
Errors (`[x]`) block the file. Warnings (`[!]`) are informational.

## 3. Try it in the lab, then scan

```
python3 php2shell.pyz -t targets.txt --scope scope.txt --authorized --advisory php-xxxx.json -o out/xxxx --formats html,json,nessus
```
If you can, start one unpatched and one patched build with the images in `tests/oracle_lab.py` and check the banner
verdicts.

## Out of scope

Only PHP core vulnerabilities are supported. Other runtimes (Node, OpenSSL, Java) do not fingerprint the same way
remotely (no version header, or an unreliable one) and need their own host checks; they are not scanned with this
advisory engine.
