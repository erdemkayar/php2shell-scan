"""Async scan engine: target parsing, TCP pre-filter, raw HTTP(S) fetch, rate limiting, JSONL checkpoint."""
import asyncio
import ipaddress
import json
import os
import re
import secrets
import ssl
import sys
import time
import warnings
from collections import defaultdict
from datetime import datetime, timezone

from . import classify as C
from . import fcgi as FC
from . import oracle as O
from . import __version__

UA = f"php2shell-scanner/{__version__} (+https://github.com/erdemkayar/php2shell-scan; authorized security assessment)"
HTTPS_PORTS = {443, 8443, 9443, 4443}
HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8888, 3000}
DEEP_PATHS = ["/index.php", *(p for p, *_ in C.PHP_APPS)]
DEEP_LINKS = 2  # harvested same-host .php links fetched by --deep
MAX_BODY = 65536


# ----------------------------------------------------------------------------- targets
def _first_token(raw):
    """'10.0.0.1  prod-db  # note' -> '10.0.0.1' (scope and exclude files share this tokenising)."""
    raw = raw.split("#")[0].strip()
    return raw.split()[0] if raw else ""


def _parse_excludes(items):
    nets, hosts, problems = [], set(), []
    for no, raw in enumerate(items, 1):
        tok = _first_token(raw)
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            if not HOSTNAME_RE.match(tok) or tok.replace(".", "").isdigit():
                problems.append(f"exclude line {no}: not an IP, CIDR or hostname: '{tok}'")
            hosts.add(tok.lower().rstrip("."))
    if problems:
        raise TargetError(problems)
    return nets, hosts


def _excluded(host, ex):
    nets, hosts = ex
    if host.lower() in hosts:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in n for n in nets)


def load_scope(items):
    """Approved scope: CIDRs/IPs, exact hostnames, or *.domain wildcards. Returns None when no scope given."""
    if not items:
        return None
    nets, names, wild = [], set(), []
    for raw in items:
        raw = _first_token(raw)
        if not raw:
            continue
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            raw = raw.lower().rstrip(".")
            (wild.append(raw[1:]) if raw.startswith("*.") else names.add(raw))
    return nets, names, wild


def in_scope(host, scope):
    nets, names, wild = scope
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in n for n in nets)
    except ValueError:
        h = host.lower().rstrip(".")
        return h in names or any(h.endswith(w) for w in wild)


def apply_scope(endpoints, scope, trust_names=False):
    """Fail-closed scope enforcement on PINNED endpoints. Returns (kept, violations, gaps).
    - IP target: the IP must be inside an approved range.
    - Name target (host = resolved IP, ep['name'] = name): the IP must be inside an approved range and, if the scope
      lists names, the name must match too. With trust_names an explicitly approved name may resolve anywhere.
      A name-only scope therefore needs trust_names: otherwise a CNAME to a third party would be scanned silently.
    - Dual-stack / round-robin: addresses of an allowed name that fall outside the ranges are dropped and reported
      as gaps; only a name with NO allowed address is a violation (aborts the run)."""
    nets, names, wild = scope
    kept, violations, gaps, by_name = [], set(), set(), {}
    for e in endpoints:
        name = e.get("name")
        if not name:
            (kept.append(e) if in_scope(e["host"], scope) else violations.add(e["host"]))
            continue
        name_ok = in_scope(name, scope)
        ip_ok = in_scope(e["host"], scope)
        ok = (ip_ok and (name_ok or not (names or wild))) or (trust_names and name_ok)
        by_name.setdefault(name, []).append((e, ok))
    for name, items in by_name.items():
        if not any(ok for _, ok in items):
            for e, _ in items:
                violations.add(f"{name} -> {e['host']}")
            continue
        for e, ok in items:
            if ok:
                kept.append(e)
            else:
                gaps.add(f"{name} -> {e['host']} (address outside approved ranges, skipped)")
    return kept, sorted(violations), sorted(gaps)


def out_of_scope(endpoints, scope, trust_names=False):
    """Hosts that would violate scope (convenience wrapper around apply_scope)."""
    return apply_scope(endpoints, scope, trust_names)[1]


def resolve_endpoints(endpoints, exclude_items=(), resolver=None, workers=32, pinned=None, ipv4_only=False):
    """Resolve every hostname ONCE and pin it: the scanner then connects to the IP (with SNI/Host = name), so the
    scope check, the TCP probe and every HTTP request all hit the same, checked address (no DNS rebinding/round-robin
    surprises). Returns (pinned_endpoints, unresolved_names, answers). ipv4_only drops AAAA answers."""
    import concurrent.futures as cf
    import socket
    resolver = resolver or (lambda n: sorted({ai[4][0] for ai in socket.getaddrinfo(n, None, proto=socket.IPPROTO_TCP)}))
    names = sorted({e["host"] for e in endpoints if not _is_ip(e["host"])})
    resolved = {}
    if pinned:  # --resume: reuse the first run's answers so round-robin DNS cannot add endpoints
        good = {n: ips for n, ips in pinned.items()  # empty / tampered answers are re-resolved, never trusted
                if isinstance(ips, list) and ips and all(isinstance(i, str) and _is_ip(i) for i in ips)}
        names, resolved = [n for n in names if n not in good], {n: good[n] for n in names if n in good}
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        resolved.update(ex.map(lambda n: (n, _safe_resolve(resolver, n)), names))
    ex_rules = _parse_excludes(exclude_items)
    out, seen = [], set()
    for e in endpoints:
        if _is_ip(e["host"]):
            ips, name = [e["host"]], None
        else:
            ips, name = resolved.get(e["host"]) or [], e["host"]
        if ipv4_only:
            ips = [i for i in ips if ipaddress.ip_address(i).version == 4]
        for ip in ips:
            if _excluded(ip, ex_rules):
                continue
            ep = dict(e, host=ip)
            if name:
                ep["name"], ep["sni"] = name, e.get("sni") or name
            k = endpoint_key(ep)
            if k not in seen:
                seen.add(k)
                out.append(ep)
    return out, sorted(n for n, ips in resolved.items() if not ips), resolved


def _safe_resolve(resolver, name):
    try:
        return resolver(name)
    except OSError:
        return []


def _is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def endpoint_key(ep):
    return f"{ep['host']}:{ep['port']}" + (f"|{ep['sni']}" if ep.get("sni") else "")


class TargetError(ValueError):
    """Raised with every invalid target line, so the operator fixes the list once instead of line by line."""

    def __init__(self, problems):
        self.problems = problems
        super().__init__("; ".join(problems[:5]))


HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)*\.?$")


def _port(v):
    p = int(v)
    if not 0 < p < 65536:
        raise ValueError(f"port out of range: {v}")
    return p


def _parse_line(line, default_ports):
    """One target line -> (target, ports, scheme, path, sni, labels). Raises ValueError with a readable reason."""
    toks = line.split()
    target, attrs = toks[0], {}
    for t in toks[1:]:
        if "=" not in t:
            raise ValueError(f"unexpected token '{t}' (labels must be key=value)")
        k, v = t.split("=", 1)
        attrs[k.strip().lower()] = v.strip()
    ports = [_port(p) for p in attrs.pop("ports").split(",")] if "ports" in attrs else list(default_ports)
    sni = attrs.pop("sni", None) or attrs.pop("host", None)
    attrs.pop("host", None)
    path = attrs.pop("path", "/")
    scheme = None
    if "://" in target:
        from urllib.parse import urlparse
        u = urlparse(target)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError(f"unsupported URL '{target}'")
        scheme, target = u.scheme, u.hostname
        ports = [u.port or (443 if scheme == "https" else 80)]
        path = u.path or path
    elif target.startswith("[") and "]:" in target:  # [IPv6]:port
        target, p = target[1:].split("]:", 1)
        ports = [_port(p)]
    elif target.count(":") == 1:  # host:port / IPv4:port
        target, p = target.split(":")
        ports = [_port(p)]
    if sni and not HOSTNAME_RE.match(sni):
        raise ValueError(f"invalid sni '{sni}'")
    return target, ports, scheme, path, sni, attrs


def _expand_hosts(target, max_hosts):
    """IP/CIDR -> host list; hostname -> [hostname]. Returns (hosts, oversized_count)."""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        if not HOSTNAME_RE.match(target) or target.replace(".", "").isdigit() or "/" in target:
            raise ValueError(f"not an IP, CIDR or hostname: '{target}'") from None
        return [target], 0
    n = net.num_addresses
    if n > max_hosts:
        return [], n
    return [str(h) for h in (net.hosts() if n > 2 else net)], 0


def parse_targets(lines, default_ports, max_hosts, exclude_items=()):
    """Line format:  <host|ip|CIDR|URL|[v6]:port> [key=value ...]   (# comments)
    Reserved keys: ports=80,443  sni=name (TLS SNI + Host header)  path=/x   -- all other keys become labels.
    Returns (endpoints, skipped_oversized). Raises TargetError listing every invalid line."""
    ex = _parse_excludes(exclude_items)
    out, seen, skipped, problems = [], set(), [], []
    for no, raw in enumerate(lines, 1):
        line = raw.split("#")[0].strip()
        if not line:
            continue
        try:
            target, ports, scheme, path, sni, labels = _parse_line(line, default_ports)
            hosts, oversized = _expand_hosts(target, max_hosts)
        except ValueError as e:
            problems.append(f"line {no}: {e}")
            continue
        if oversized:
            skipped.append((target, oversized))
        for h in hosts:
            if _excluded(h, ex):
                continue
            for p in ports:
                ep = {"host": h, "port": p, "scheme": scheme, "path": path, "sni": sni, "labels": labels}
                k = endpoint_key(ep)
                if k not in seen:
                    seen.add(k)
                    out.append(ep)
    if problems:
        raise TargetError(problems)
    return out, skipped


# ----------------------------------------------------------------------------- primitives
class RateLimiter:
    """Global limiter for new connection attempts per second (0 = unlimited)."""

    def __init__(self, rate):
        self.interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self):
        if not self.interval:
            return
        async with self._lock:
            now = time.monotonic()
            if self._next < now:
                self._next = now
            delay = self._next - now
            self._next += self.interval
        if delay > 0:
            await asyncio.sleep(delay)


async def tcp_open(host, port, timeout, limiter=None):
    """Returns (open: bool, reason: 'open'|'refused'|'timeout'|'error')."""
    if limiter:
        await limiter.wait()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except asyncio.TimeoutError:
        return False, "timeout"
    except ConnectionRefusedError:
        return False, "refused"
    except OSError as e:
        return False, "refused" if getattr(e, "errno", None) in (111, 61, 10061) else "error"
    try:
        w.close()
        await w.wait_closed()
    except Exception:
        pass
    return True, "open"


def _tls_info(ssl_obj):
    """CN/SAN/issuer/notAfter if 'cryptography' is installed; otherwise empty."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtensionOID
        der = ssl_obj.getpeercert(binary_form=True)
        if not der:
            return {}
        cert = x509.load_der_x509_certificate(der)
        cn = next((a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)), "")
        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
        except Exception:
            san = []
        iss = next((a.value for a in cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)), "")
        return {"cn": cn, "san": list(san)[:20], "issuer": iss, "not_after": cert.not_valid_after_utc.isoformat()
                if hasattr(cert, "not_valid_after_utc") else str(cert.not_valid_after)}
    except Exception:
        return {}


def _tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we fingerprint, we do not trust: self-signed/expired certs must still be read
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:  # LibreSSL has no SECLEVEL syntax
        pass
    try:  # EOL PHP hosts often speak only TLS 1.0/1.1; modern defaults would make them invisible
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    return ctx


def _host_header(host, sni, port, tls):
    h = sni or host
    if ":" in h and not h.startswith("["):
        h = f"[{h}]"
    return h if port == (443 if tls else 80) else f"{h}:{port}"


async def _read_until(reader, limit, timeout):
    """Read until EOF, `limit` bytes or the overall deadline - partial data is returned, not discarded."""
    buf, deadline = b"", time.monotonic() + timeout
    while len(buf) < limit:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(8192), left)
        except asyncio.TimeoutError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


MULTI_HEADERS = {"x-powered-by", "server", "x-generator", "via"}
CHUNK_SIZE_RE = re.compile(rb"^[0-9A-Fa-f]{1,8}$")
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _dechunk(body):
    """Best-effort Transfer-Encoding: chunked decoding of a possibly truncated body.
    Hostile input (negative/huge/non-hex sizes) falls back to the raw bytes; the cursor always moves forward."""
    out, i = b"", 0
    while i < len(body):
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        size = body[i:j].split(b";")[0].strip()
        if not CHUNK_SIZE_RE.match(size):
            return body if not out else out
        n = int(size, 16)
        if n == 0:
            break
        out += body[j + 2:j + 2 + n]
        i = j + 2 + n + 2  # strictly increasing: n >= 1
    return out


def clean(s):
    """Strip control characters from untrusted banner text (they break XLSX/DOCX writers and terminals)."""
    return CTRL_RE.sub("", s) if isinstance(s, str) else s


def parse_http_response(buf):
    """Raw bytes -> (status, headers{lower: first value}, cookies[], body str). Raises ValueError if not HTTP."""
    m = re.search(rb"\r?\n\r?\n", buf)
    head, body = (buf[:m.start()], buf[m.end():]) if m else (buf, b"")
    if not head.startswith(b"HTTP/"):
        raise ValueError("not an HTTP response")
    lines = re.split(r"\r?\n", head.decode("latin-1"))
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        raise ValueError("bad status line") from None
    headers, cookies = {}, []
    for ln in lines[1:]:
        k, sep, v = ln.partition(":")
        if not sep:
            continue
        k, v = k.strip().lower(), clean(v.strip())
        if k == "set-cookie":
            cookies.append(v)
        elif k in headers and k in MULTI_HEADERS:  # e.g. 'X-Powered-By: PleskLin' then 'X-Powered-By: PHP/8.1.10'
            headers[k] += ", " + v
        elif k not in headers:
            headers[k] = v
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    return status, headers, cookies, clean(body[:MAX_BODY].decode("utf-8", "replace"))


async def http_get(host, port, tls, sni, path, timeout, hs_timeout=None, limiter=None, method="GET", body=b"", headers=None):
    """Raw HTTP/1.1 request (GET unless --oracle sends its POST). Returns dict(path,status,headers,cookies,body,tls)."""
    if limiter:
        await limiter.wait()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=_tls_context() if tls else None, server_hostname=(sni or host) if tls else None),
        min(timeout, hs_timeout) if hs_timeout else timeout)
    try:
        tinfo = _tls_info(writer.get_extra_info("ssl_object")) if tls else {}
        extra = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
        if body:
            extra += f"Content-Length: {len(body)}\r\n"
        writer.write((f"{method} {path} HTTP/1.1\r\nHost: {_host_header(host, sni, port, tls)}\r\nUser-Agent: {UA}\r\n"
                      f"Accept: */*\r\n{extra}Connection: close\r\n\r\n").encode() + body)
        await writer.drain()
        buf = await _read_until(reader, MAX_BODY + 8192, timeout)
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), 2)
        except Exception:  # noqa: BLE001 - peer may already be gone; nothing to recover
            pass
    status, headers, cookies, body = parse_http_response(buf)
    return {"path": path, "status": status, "headers": headers, "cookies": cookies, "body": body, "tls": tinfo}


def _scheme_candidates(ep):
    if ep.get("scheme"):
        return [ep["scheme"]]
    p = ep["port"]
    if p in HTTPS_PORTS:
        return ["https"]
    if p in HTTP_PORTS:
        return ["http"]
    return ["http", "https"]  # ambiguous port: plain HTTP first (TLS servers reject it fast; plain servers stall on a TLS hello)


async def fetch_with_redirects(host, port, scheme, sni, path, timeout, hs_timeout=None, limiter=None, allowed_ports=None):
    """Follow up to 3 redirects that stay on the same (pinned) host and on an approved port.
    A failing later hop never discards what was already collected. Returns (responses, scheme, port, note)."""
    from urllib.parse import urljoin, urlparse
    out, note, good = [], "", (scheme, port)
    for _ in range(4):
        try:
            r = await http_get(host, port, scheme == "https", sni, path, timeout, hs_timeout, limiter)
        except Exception as e:  # noqa: BLE001
            if not out:
                raise
            note = f"redirect hop {scheme}://{sni or host}:{port} failed ({type(e).__name__})"
            scheme, port = good  # report (and deep-probe) the last hop that actually answered
            break
        out.append(r)
        good = (scheme, port)
        loc = r["headers"].get("location")
        if r["status"] not in (301, 302, 303, 307, 308) or not loc:
            break
        u = urlparse(urljoin(f"{scheme}://{sni or host}:{port}{path}", loc))
        nport = u.port or (443 if u.scheme == "https" else 80)
        if (u.hostname or "").lower() not in {(sni or host).lower(), host.lower()} or u.scheme not in ("http", "https"):
            note = f"redirects to {u.hostname} (not followed: other host)"
            break
        if allowed_ports is not None and nport not in allowed_ports:
            note = f"redirects to port {nport} (not followed: port not in scan scope)"
            break
        scheme, port, path = u.scheme, nport, (u.path or "/") + (f"?{u.query}" if u.query else "")
    return out, scheme, port, note


async def _connect(ep, opts):
    """TCP probe with retries on timeout/transient errors (a refusal is final)."""
    reason = "error"
    for _ in range(1 + opts.get("retries", 1)):
        ok, reason = await tcp_open(ep["host"], ep["port"], opts["connect_timeout"], opts.get("limiter"))
        if ok or reason == "refused":
            return ok, reason
    return False, reason


async def _first_response(ep, opts):
    """Try the candidate schemes; retry transport failures, never protocol rejections.
    Returns (responses, scheme, effective_port, note, last_error)."""
    cands = _scheme_candidates(ep)
    ambiguous = len(cands) > 1
    to = min(opts["http_timeout"], 5.0) if ambiguous else opts["http_timeout"]
    rejected, last_err = set(), ""
    for _ in range(1 + opts.get("retries", 1)):
        for sch in (c for c in cands if c not in rejected):
            try:
                resp, sch_used, port_used, note = await fetch_with_redirects(
                    ep["host"], ep["port"], sch, ep.get("sni"), ep["path"], to, opts.get("tls_timeout"), opts.get("limiter"), opts.get("allowed_ports"))
            except (ssl.SSLError, ValueError) as e:  # handshake/protocol mismatch: deterministic
                last_err = f"{type(e).__name__}: {e}"
                rejected.add(sch)
                continue
            except Exception as e:  # noqa: BLE001 - timeouts/resets: retried in the next round
                last_err = f"{type(e).__name__}: {e}"
                continue
            if ambiguous and sch == "http" and resp[-1]["status"] == 400 and re.search(r"HTTPS|SSL|TLS", resp[-1]["body"], re.I):
                last_err = "plain HTTP rejected (TLS port)"
                rejected.add("http")
                continue
            return resp, sch_used, port_used, note, ""
        if len(rejected) == len(cands):
            break
    return [], None, ep["port"], "", last_err


async def scan_endpoint(ep, opts):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ok, reason = await _connect(ep, opts)
    if not ok:  # compact record: closed endpoints dominate large scans
        return {"key": endpoint_key(ep), "host": ep["host"], "port": ep["port"], "status": "CLOSED",
                "closed_reason": reason, "scanned_at": now}
    res = {"key": endpoint_key(ep), "host": ep["host"], "port": ep["port"], "sni": ep.get("sni") or "", "name": ep.get("name") or "",
           "labels": ep.get("labels", {}), "scheme": "", "status": "OPEN_NO_HTTP", "confidence": "", "php_version": "",
           "indicators": [], "cms_hint": "", "server": "", "x_powered_by": "", "http_status": "", "note": "",
           "tls": {}, "scanned_at": now}
    responses, used_scheme, eff_port, note, last_err = await _first_response(ep, opts)
    if not responses:
        f = await FC.probe(ep["host"], ep["port"], min(opts["http_timeout"], 5.0), opts.get("limiter"))
        if f:
            st, conf, note = C.fpm_status(f)
            res.update(scheme="fastcgi", status=st, confidence=conf, php_version=f["php_version"],
                       indicators=["fastcgi" + (":php" if f["php"] else "")], note=note, fastcgi=f)
            return res
        res["note"] = f"port open, no HTTP(S) response ({last_err})"
        return res
    res.update(scheme=used_scheme, note=note, tls=next((r["tls"] for r in responses if r.get("tls")), {}))
    own_path = responses[-1]["path"]  # where the endpoint's redirects ended, before --deep adds its probe paths
    names = {n.lower() for n in (ep["host"], ep.get("sni"), ep.get("name")) if n}
    links = C.harvest_php_links(responses[-1]["body"], names, own_path)
    probe, catch_all = [], False
    if opts["deep"]:
        # a random .php first: a server answering 200 to anything makes a bare 200 on a .php path meaningless
        baseline = f"/p2s-{secrets.token_hex(4)}.php"
        for p in [baseline, *DEEP_PATHS, *links[:DEEP_LINKS]]:
            try:
                r, _, _, _ = await fetch_with_redirects(ep["host"], eff_port, used_scheme, ep.get("sni"), p,
                                                        opts["http_timeout"], opts.get("tls_timeout"), opts.get("limiter"), opts.get("allowed_ports"))
            except Exception:  # noqa: BLE001 - optional probe paths; absence is not an error
                continue
            if p == baseline:
                catch_all = r[-1]["status"] == 200
            responses.extend(r)
            probe.append(p)
    fp = C.detect(responses, probe, catch_all)  # harvested links feed --deep/--oracle; a link alone proves nothing
    st, conf, ver, bnote = C.banner_status(fp)
    if opts.get("oracle"):
        first = [own_path] if own_path.endswith(".php") or fp["indicators"] else []
        cands = list(dict.fromkeys([*first, *links, *O.PATHS, own_path]))[:O.MAX_POSTS]
        res["oracle"] = await run_oracle(ep, opts, eff_port, used_scheme, cands, responses)
        st, conf, bnote = C.apply_oracle(st, conf, bnote, res["oracle"])
    res.update(status=st, confidence=conf, php_version=ver, indicators=fp["indicators"], cms_hint=",".join(fp["cms"]),
               server=fp["server"], x_powered_by=fp["x_powered_by"], http_status=fp["http_status"],
               note=(note + "; " if note else "") + bnote, php_links=links)
    if catch_all:
        res["catch_all"] = True
    return res


async def run_oracle(ep, opts, port, scheme, paths, responses):
    """--oracle: POST the probe to each candidate path (at most O.MAX_POSTS); stop at the first verdict.
    Candidates: the endpoint's own path when it already looks like PHP, harvested .php links, /index.php, the own path.
    Never redirected, rate limited like every other connection."""
    names = O.session_names([c for r in responses for c in r["cookies"]])
    out = {"result": "SILENT", "markers": 0, "path": "", "http_status": "", "handler": "", "session_names": names}
    for p in paths:
        ctype, cookie, body = O.build(names)
        try:
            r = await http_get(ep["host"], port, scheme == "https", ep.get("sni"), p, opts["http_timeout"], opts.get("tls_timeout"),
                               opts.get("limiter"), method="POST", body=body, headers={"Content-Type": ctype, "Cookie": cookie})
        except Exception as e:  # noqa: BLE001 - an unanswered probe is "no verdict", never an endpoint error
            out.setdefault("error", f"{type(e).__name__}: {e}")
            continue
        res, n, handler = O.evaluate(r["body"])
        if n >= out["markers"]:
            out.update(result=res, markers=n, path=p, http_status=r["status"], handler=handler)
        if O.is_decisive(res):
            break
    if out["markers"] == 0 and "error" in out and not out["http_status"]:
        out["result"] = "ERROR"
    return out


# ----------------------------------------------------------------------------- checkpoint store
class Store:
    def __init__(self, path, resume):
        self.path, self.done = path, set()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if resume and os.path.exists(path):
            with open(path) as f:
                for ln in f:
                    try:
                        o = json.loads(ln)
                    except Exception:
                        continue  # torn last line after a crash
                    if o.get("status") == "ERROR":
                        self.done.discard(o["key"])  # transient failure: retry on resume
                    else:
                        self.done.add(o["key"])
        elif os.path.exists(path):
            os.replace(path, path + ".prev")
        torn = False
        if os.path.exists(path) and os.path.getsize(path):
            with open(path, "rb") as f:
                f.seek(-1, os.SEEK_END)
                torn = f.read(1) != b"\n"
        self._f = open(path, "a", buffering=1)
        if torn:  # crash mid-line: terminate it so the next record is not glued onto garbage
            self._f.write("\n")

    def write(self, obj):
        self._f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        if obj.get("status") != "ERROR":
            self.done.add(obj["key"])

    def close(self):
        self._f.close()


def load_results(path, skip_closed=False, stats=None):
    """Last record per endpoint wins (a resumed retry supersedes an earlier ERROR).
    skip_closed: keep only endpoints that answered (memory stays proportional to live services, not to the
    address space); stats, if a dict, receives total / closed counts."""
    out, closed = {}, set()
    with open(path) as f:
        for ln in f:
            try:
                o = json.loads(ln)
            except Exception:
                continue
            k = o["key"]
            if skip_closed and o.get("status") == "CLOSED":
                out.pop(k, None)
                closed.add(k)
                continue
            closed.discard(k)
            out[k] = o
    if stats is not None:
        stats.update(total=len(out) + len(closed), closed=len(closed))
    return list(out.values())


# ----------------------------------------------------------------------------- orchestrator
def estimate_seconds(n_endpoints, opts):
    rate = opts["rate"] or 1e9
    conc = max(1, opts["concurrency"])
    # worst case: every endpoint times out on connect, including retries
    tries = 1 + opts.get("retries", 1)
    return max(n_endpoints * tries / rate, n_endpoints * tries * opts["connect_timeout"] / conc)


async def run_scan(endpoints, opts, store, quiet=False):
    todo = [e for e in endpoints if endpoint_key(e) not in store.done]
    total, skipped = len(todo), len(endpoints) - len(todo)
    if skipped and not quiet:
        print(f"[*] resume: {skipped} endpoint(s) already done, {total} remaining", file=sys.stderr)
    limiter = RateLimiter(opts["rate"])
    opts = dict(opts, limiter=limiter)
    host_sem = defaultdict(lambda: asyncio.Semaphore(opts["per_host"]))
    queue = asyncio.Queue()
    for e in todo:
        queue.put_nowait(e)
    stats = {"done": 0, "open": 0, "http": 0, "act": 0}
    t0 = time.monotonic()

    async def worker():
        while True:
            try:
                ep = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            async with host_sem[ep["host"]]:
                try:
                    r = await scan_endpoint(ep, opts)
                except Exception as e:  # noqa: BLE001
                    r = {"key": endpoint_key(ep), "host": ep["host"], "port": ep["port"], "sni": ep.get("sni") or "",
                         "labels": ep.get("labels", {}), "status": "ERROR", "note": f"{type(e).__name__}: {e}"}
            store.write(r)
            stats["done"] += 1
            if r["status"] not in ("CLOSED", "ERROR"):
                stats["open"] += 1
            if r["status"] not in ("CLOSED", "OPEN_NO_HTTP", "ERROR"):
                stats["http"] += 1
                if C.is_actionable(r["status"]):
                    stats["act"] += 1

    async def progress():
        while True:
            await asyncio.sleep(5)
            el = time.monotonic() - t0
            rate = stats["done"] / el if el else 0
            eta = (total - stats["done"]) / rate if rate else 0
            print(f"[*] {stats['done']}/{total} done | open {stats['open']} | http {stats['http']} | "
                  f"actionable {stats['act']} | {rate:.0f}/s | ETA {eta/60:.1f} min", file=sys.stderr)

    ptask = None if quiet else asyncio.create_task(progress())
    workers = [asyncio.create_task(worker()) for _ in range(min(opts["concurrency"], max(total, 1)))]
    try:
        await asyncio.gather(*workers)
    finally:
        for w in workers:
            w.cancel()
        if ptask:
            ptask.cancel()
    stats["seconds"] = time.monotonic() - t0
    stats["total"] = total
    return stats
