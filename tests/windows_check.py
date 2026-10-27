"""Checks the JSON that p2s/collect_windows.ps1 wrote on a real Windows host (CI job windows-collector).

The job installs IIS + CGI and PHP (Chocolatey), registers php-cgi.exe as an IIS FastCGI application, plants a file
with a webshell pattern in the site root, runs the collector with -Ioc as Administrator, and then runs this script:
  python tests/windows_check.py host.json <php-cgi.exe path> <planted file>
It also imports the file through the real CLI (--import-local) so the scanner side is exercised end to end."""
import json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from p2s import classify as C, verify as V  # noqa: E402

FAIL = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  ({detail})" if detail else ""), flush=True)
    if not cond:
        FAIL.append(name)


def main(path, cgi, planted):
    doc = json.load(open(path, encoding="utf-8-sig"))
    out = doc.get("output", "")
    print(out)
    rec, ips = V.load_local(doc)
    d = V.parse_output(out)
    bins = [b["path"].lower() for b in d["bins"]]
    check("collector found php-cgi.exe registered in IIS FastCGI", cgi.lower() in bins and f"IIS_FASTCGI={cgi}".lower() in out.lower(),
          str(bins))
    check("every PHP build reported a version", d["bins"] and all(V.PHP_V.search(b["banner"] or "") for b in d["bins"]),
          str([b["banner"][:40] for b in d["bins"]]))
    check("verdict is decisive (upstream Windows builds have no backports)", rec["verdict"] in ("VULNERABLE", "PATCHED", "VULNERABLE_EOL"),
          f"{rec['verdict']}: {rec['summary'][:160]}")
    check("addresses collected for --import-local mapping", bool(ips), str(ips))
    ioc = rec.get("ioc") or {}
    check("IoC ran as Administrator and found the planted file",
          ioc.get("priv") == "root" and any(os.path.normcase(planted) == os.path.normcase(p) for p in ioc.get("shells", [])),
          f"priv={ioc.get('priv')} shells={ioc.get('shells')}")
    check("mitigation evaluated for the IIS php.ini", rec["mitigation"]["state"] is not None or not d["ini_sets"], str(rec["mitigation"]))
    with tempfile.TemporaryDirectory() as t:
        p = subprocess.run([sys.executable, os.path.join(os.path.dirname(HERE), "php2shell_scan.py"), "-t", "127.0.0.1", "--ports", "1",
                            "--no-scope", "--authorized", "--import-local", path, "-o", t, "--formats", "json"],
                           capture_output=True, text=True, timeout=300)
        a = json.load(open(os.path.join(t, "assets.json"), encoding="utf-8"))["assets"]
        check("CLI imported the Windows result; IoC hit makes it compromise-suspected",
              any(x.get("closure") == "COMPROMISE_SUSPECTED" for x in a), f"rc={p.returncode} {[(x['host'], x.get('closure')) for x in a]}")
    print("\n" + ("ALL PASSED" if not FAIL else f"{len(FAIL)} FAILED: {FAIL}"))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
