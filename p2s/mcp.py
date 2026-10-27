"""MCP server (stdio, newline-delimited JSON-RPC 2.0): php2shell.pyz --mcp

Tools wrap the CLI, so every safety rule of the CLI applies unchanged (scope enforcement, pinned DNS, rate limit). An
agent cannot waive the scope (no --no-scope here) and must state authorization explicitly on every scan call.
  php2shell_plan         dry run: endpoint count and worst-case time, no traffic
  php2shell_scan         scan (optionally --oracle / --deep) into out_dir, returns php2shell.findings/1
  php2shell_findings     read findings.json of an earlier run
  php2shell_verify_pack  check an evidence pack
"""
import json
import os
import subprocess
import sys

from . import __version__

PROTOCOL = "2025-06-18"
_list = {"type": "array", "items": {"type": "string"}, "minItems": 1}
TOOLS = [
    {"name": "php2shell_plan", "description": "Dry run: how many endpoints the targets expand to, whether they are inside the scope, "
                                              "worst-case duration. Sends no traffic.",
     "inputSchema": {"type": "object", "required": ["targets", "scope"], "additionalProperties": False,
                     "properties": {"targets": _list, "scope": _list, "ports": {"type": "string"}}}},
    {"name": "php2shell_scan", "description": "Scan authorized targets for CVE-2026-109618/-109619 exposure and write reports to out_dir. "
                                              "Requires authorized=true (the operator holds written authorization) and an approved scope. "
                                              "oracle=true sends up to 2 small multipart POSTs per endpoint.",
     "inputSchema": {"type": "object", "required": ["targets", "scope", "authorized", "out_dir"], "additionalProperties": False,
                     "properties": {"targets": _list, "scope": _list, "authorized": {"type": "boolean", "const": True},
                                    "out_dir": {"type": "string"}, "ports": {"type": "string"}, "oracle": {"type": "boolean"},
                                    "deep": {"type": "boolean", "description": "default true; false sends only the endpoint's own GET"}, "rate": {"type": "number", "minimum": 1, "maximum": 1000},
                                    "lang": {"enum": ["tr", "en"]}}}},
    {"name": "php2shell_findings", "description": "Return findings.json (php2shell.findings/1) of an earlier run.",
     "inputSchema": {"type": "object", "required": ["out_dir"], "additionalProperties": False, "properties": {"out_dir": {"type": "string"}}}},
    {"name": "php2shell_verify_pack", "description": "Verify an evidence pack (hashes; signature when allowed_signers is given).",
     "inputSchema": {"type": "object", "required": ["path"], "additionalProperties": False,
                     "properties": {"path": {"type": "string"}, "allowed_signers": {"type": "string"}, "signer_identity": {"type": "string"}}}},
]


def _cli(args, timeout=24 * 3600):
    entry = os.path.abspath(sys.argv[0])
    p = subprocess.run([sys.executable, entry, *args], capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def _findings(out_dir):
    with open(os.path.join(out_dir, "findings.json"), encoding="utf-8") as f:
        return json.load(f)


def call(name, a):
    """(result dict, is_error)."""
    if name == "php2shell_plan":
        rc, so, se = _cli(["-t", *a["targets"], "--scope", *a["scope"], "--list"] + (["--ports", a["ports"]] if a.get("ports") else []),
                          timeout=600)
        return {"exit_code": rc, "output": (se + so).strip()[-4000:]}, rc != 0
    if name == "php2shell_scan":
        if a.get("authorized") is not True:
            return {"error": "authorized must be true: scan only with written authorization"}, True
        args = ["-t", *a["targets"], "--scope", *a["scope"], "--authorized", "-o", a["out_dir"], "--formats", "json,findings,html",
                "--lang", a.get("lang", "en")]
        args += ["--ports", a["ports"]] if a.get("ports") else []
        args += ["--rate", str(a["rate"])] if a.get("rate") else []
        args += ["--oracle"] if a.get("oracle") else []
        args += ["--no-deep"] if a.get("deep") is False else []
        rc, so, se = _cli(args)
        if rc not in (0, 2, 3):
            return {"exit_code": rc, "error": (se + so).strip()[-4000:]}, True
        doc = _findings(a["out_dir"])
        return {"exit_code": rc, "meaning": {0: "nothing actionable", 2: "actionable assets", 3: "coverage incomplete"}[rc],
                "report": os.path.join(a["out_dir"], "report.html"), **doc}, False
    if name == "php2shell_findings":
        try:
            return _findings(a["out_dir"]), False
        except (OSError, ValueError) as e:
            return {"error": str(e)}, True
    if name == "php2shell_verify_pack":
        args = ["--verify-pack", a["path"]]
        if a.get("allowed_signers"):
            args += ["--allowed-signers", a["allowed_signers"], "--signer-identity", a.get("signer_identity", "")]
        rc, so, se = _cli(args, timeout=600)
        return {"verified": rc == 0, "output": (so + se).strip()[-4000:]}, rc != 0
    return {"error": f"unknown tool {name}"}, True


def handle(msg):
    """One JSON-RPC message -> response dict (None for notifications)."""
    mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if mid is None:
        return None
    if method == "initialize":
        res = {"protocolVersion": params.get("protocolVersion", PROTOCOL), "capabilities": {"tools": {}},
               "serverInfo": {"name": "php2shell-scanner", "version": __version__}}
    elif method == "tools/list":
        res = {"tools": TOOLS}
    elif method == "tools/call":
        tool = next((t for t in TOOLS if t["name"] == params.get("name")), None)
        args = params.get("arguments") or {}
        if not tool:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool {params.get('name')}"}}
        missing = [k for k in tool["inputSchema"]["required"] if k not in args]
        unknown = [k for k in args if k not in tool["inputSchema"]["properties"]]
        if missing or unknown:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"missing {missing} / unknown {unknown}"}}
        try:
            out, err = call(tool["name"], args)
        except Exception as e:  # noqa: BLE001 - surface to the agent instead of killing the server
            out, err = {"error": f"{type(e).__name__}: {e}"}, True
        res = {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}], "structuredContent": out, "isError": err}
    elif method == "ping":
        res = {}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": mid, "result": res}


def serve(stdin=sys.stdin, stdout=sys.stdout):
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            resp = handle(msg)
        if resp is not None:
            stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            stdout.flush()
