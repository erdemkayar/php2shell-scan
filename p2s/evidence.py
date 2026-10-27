"""Evidence pack (--evidence-pack): one zip an auditor can check without trusting the person who hands it over.

Contents: raw results, host checks, reports, the scope files, the advisory that drove the verdicts, the (redacted)
command line, and manifest.json with the SHA-256 of every file. --sign-key signs the manifest with an OpenSSH key
(`ssh-keygen -Y sign`, namespace php2shell-evidence): no extra dependency, verifiable with stock OpenSSH.
--verify-pack re-hashes every file and, given an allowed_signers file, verifies the signature."""
import hashlib
import json
import os
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone

from . import __version__
from . import classify as C

FORMAT = "php2shell.evidence/1"
NAMESPACE = "php2shell-evidence"
OUTPUTS = ("results.jsonl", "assets.json", "verify.json", "passive.json", "meta.json", "dns.json",
           "report.html", "report.xlsx", "report.docx", "assets.csv", "assets.sarif", "findings.json", "defectdojo.json",
           "findings.nessus")
SECRET_FLAGS = {"--shodan-key"}


def redact_argv(argv):
    out, skip = [], False
    for x in argv:
        if skip:
            out.append("<redacted>")
            skip = False
        elif x in SECRET_FLAGS:
            out.append(x)
            skip = True
        elif any(x.startswith(f + "=") for f in SECRET_FLAGS):
            out.append(x.split("=", 1)[0] + "=<redacted>")
        else:
            out.append(x)
    return out


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def build(outdir, scope_files=(), argv=(), sign_key=None, name=None):
    """Write the evidence zip into outdir; returns (path, manifest)."""
    members = {}
    for n in OUTPUTS:
        p = os.path.join(outdir, n)
        if os.path.isfile(p):
            members[n] = open(p, "rb").read()
    for f in scope_files:
        if os.path.isfile(f):
            members["scope/" + os.path.basename(f)] = open(f, "rb").read()
    members["advisory.json"] = json.dumps(C.ADVISORY, indent=1, ensure_ascii=False).encode()
    members["command.txt"] = (" ".join(redact_argv(list(argv))) + "\n").encode()
    manifest = {"format": FORMAT, "tool_version": __version__, "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "advisory": C.ADVISORY.get("id", ""), "files": {n: {"sha256": _sha(b), "size": len(b)} for n, b in sorted(members.items())}}
    mbytes = json.dumps(manifest, indent=1, sort_keys=True).encode()
    sig = sign(mbytes, sign_key) if sign_key else None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(outdir, name or f"evidence-{stamp}.zip")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in sorted(members.items()):
            z.writestr(n, b)
        z.writestr("manifest.json", mbytes)
        if sig:
            z.writestr("manifest.json.sig", sig)
    return path, manifest


def sign(data, key):
    with tempfile.TemporaryDirectory() as t:
        f = os.path.join(t, "manifest.json")
        open(f, "wb").write(data)
        p = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", os.path.expanduser(key), "-n", NAMESPACE, f],
                           capture_output=True, text=True, timeout=60)
        if p.returncode or not os.path.exists(f + ".sig"):
            raise RuntimeError(f"ssh-keygen -Y sign failed: {p.stderr.strip()[-300:]}")
        return open(f + ".sig", "rb").read()


def verify(path, allowed_signers=None, identity=None):
    """(ok, lines). Every file must match the manifest, nothing may be added or missing; with allowed_signers the
    manifest signature must verify for `identity`."""
    lines, ok = [], True
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        if "manifest.json" not in names:
            return False, ["manifest.json missing"]
        mbytes = z.read("manifest.json")
        m = json.loads(mbytes)
        if m.get("format") != FORMAT:
            return False, [f"unknown format {m.get('format')!r}"]
        for n, meta in m["files"].items():
            if n not in names:
                ok = False
                lines.append(f"MISSING  {n}")
            elif _sha(z.read(n)) != meta["sha256"]:
                ok = False
                lines.append(f"MODIFIED {n}")
        extra = names - set(m["files"]) - {"manifest.json", "manifest.json.sig"}
        for n in sorted(extra):
            ok = False
            lines.append(f"ADDED    {n}")
        lines.append(f"{len(m['files'])} files checked against manifest (tool {m.get('tool_version')}, {m.get('created_at')})")
        sig = z.read("manifest.json.sig") if "manifest.json.sig" in names else None
    if allowed_signers:
        if not sig:
            return False, lines + ["signature missing"]
        with tempfile.TemporaryDirectory() as t:
            s = os.path.join(t, "m.sig")
            open(s, "wb").write(sig)
            p = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", allowed_signers, "-I", identity or "", "-n", NAMESPACE, "-s", s],
                               input=mbytes, capture_output=True, timeout=60)
        good = p.returncode == 0
        ok = ok and good
        lines.append(("signature OK: " if good else "signature FAILED: ") + (p.stdout or p.stderr).decode(errors="replace").strip()[:200])
    elif sig:
        lines.append("signature present (not verified: pass --allowed-signers)")
    return ok, lines
