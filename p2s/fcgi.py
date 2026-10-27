"""Exposed FastCGI (PHP-FPM) check for open ports that do not speak HTTP.

An internet-reachable PHP-FPM socket is remote code execution on its own (a client sets PHP_VALUE / the script path),
independent of the PHP2Shell patch level. Two benign records are sent, nothing runs:
  1. FCGI_GET_VALUES (management record): any FastCGI server answers FCGI_GET_VALUES_RESULT.
  2. a responder request for a script that does not exist (/p2s-<random>.php): PHP-FPM answers "File not found." /
     "Primary script unknown" with its X-Powered-By header. No PHP_VALUE / PHP_ADMIN_VALUE, no body, no file read.
Validated against php:8.5.11-fpm in tests/oracle_lab.py."""
import asyncio
import re
import secrets
import struct

VERSION, BEGIN, END, PARAMS, STDIN, STDOUT, STDERR, GET_VALUES, GET_VALUES_RESULT = 1, 1, 3, 4, 5, 6, 7, 9, 10
MAX_READ = 16384


def _pairs(items):
    out = b""
    for k, v in items:
        k, v = k.encode(), v.encode()
        for n in (len(k), len(v)):
            out += bytes([n]) if n < 128 else struct.pack(">I", n | 0x80000000)
        out += k + v
    return out


def record(rtype, req_id, content=b""):
    return struct.pack(">BBHHBB", VERSION, rtype, req_id, len(content), 0, 0) + content


def get_values_request():
    return record(GET_VALUES, 0, _pairs([("FCGI_MAX_CONNS", ""), ("FCGI_MAX_REQS", ""), ("FCGI_MPXS_CONNS", "")]))


def missing_script_request(host="localhost"):
    script = f"/p2s-{secrets.token_hex(6)}.php"
    params = _pairs([("SCRIPT_FILENAME", "/nonexistent" + script), ("SCRIPT_NAME", script), ("REQUEST_URI", script),
                     ("REQUEST_METHOD", "GET"), ("SERVER_PROTOCOL", "HTTP/1.1"), ("GATEWAY_INTERFACE", "CGI/1.1"),
                     ("SERVER_SOFTWARE", "p2s"), ("SERVER_NAME", host), ("QUERY_STRING", "")])
    return (record(BEGIN, 1, struct.pack(">HB5x", 1, 0)) + record(PARAMS, 1, params) + record(PARAMS, 1)
            + record(STDIN, 1))


def parse_records(buf):
    """[(type, content)] for every complete record in buf; malformed input ends the list."""
    out, i = [], 0
    while i + 8 <= len(buf):
        ver, rtype, _rid, clen, plen, _ = struct.unpack(">BBHHBB", buf[i:i + 8])
        if ver != VERSION or i + 8 + clen + plen > len(buf):
            break
        out.append((rtype, buf[i + 8:i + 8 + clen]))
        i += 8 + clen + plen
    return out


def _decode_pairs(data):
    out, i = {}, 0
    try:
        while i < len(data):
            lens = []
            for _ in range(2):
                if data[i] < 128:
                    lens.append(data[i])
                    i += 1
                else:
                    lens.append(struct.unpack(">I", data[i:i + 4])[0] & 0x7FFFFFFF)
                    i += 4
            k, v = data[i:i + lens[0]], data[i + lens[0]:i + lens[0] + lens[1]]
            i += lens[0] + lens[1]
            out[k.decode("latin-1")] = v.decode("latin-1")
    except (IndexError, struct.error):
        pass
    return out


VER_RE = re.compile(r"X-Powered-By:\s*PHP/(\d+\.\d+\.\d+[^\s;,]*)", re.I)


def interpret(values_buf, script_buf):
    """dict(fastcgi, php, php_version, values, evidence) from the two raw replies."""
    vals = {}
    for t, c in parse_records(values_buf):
        if t == GET_VALUES_RESULT:
            vals.update(_decode_pairs(c))
    recs = parse_records(script_buf)
    stdout = b"".join(c for t, c in recs if t == STDOUT).decode("latin-1", "replace")
    stderr = b"".join(c for t, c in recs if t == STDERR).decode("latin-1", "replace")
    m = VER_RE.search(stdout)
    php = bool(m) or "Primary script unknown" in stderr + stdout or re.search(r"X-Powered-By:\s*PHP", stdout, re.I) is not None
    fastcgi = bool(vals) or any(t in (STDOUT, END) for t, _ in recs)
    ev = [f"FCGI_GET_VALUES_RESULT {vals}"] if vals else []
    if stdout:
        ev.append("responder: " + " | ".join(ln.strip() for ln in stdout.splitlines()[:3] if ln.strip())[:200])
    return {"fastcgi": fastcgi, "php": php, "php_version": m[1] if m else "", "values": vals, "evidence": "; ".join(ev)}


async def _exchange(host, port, payload, timeout, limiter=None):
    if limiter:
        await limiter.wait()
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        writer.write(payload)
        await writer.drain()
        buf, loop = b"", asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while len(buf) < MAX_READ:
            left = deadline - loop.time()
            if left <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(4096), left)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf += chunk
            if any(t == END for t, _ in parse_records(buf)) or any(t == GET_VALUES_RESULT for t, _ in parse_records(buf)):
                break
        return buf
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 2)
        except Exception:  # noqa: BLE001 - peer may already be gone
            pass


async def probe(host, port, timeout, limiter=None):
    """None when the port does not speak FastCGI; otherwise interpret()'s dict."""
    try:
        values = await _exchange(host, port, get_values_request(), timeout, limiter)
    except Exception:  # noqa: BLE001 - not reachable / reset: not FastCGI
        return None
    if not parse_records(values):
        return None
    try:
        script = await _exchange(host, port, missing_script_request(), timeout, limiter)
    except Exception:  # noqa: BLE001
        script = b""
    out = interpret(values, script)
    return out if out["fastcgi"] else None
