"""Opt-in behavioural check (--oracle): one small multipart POST per endpoint, no exploit and no memory pressure.

The request carries an invalid session id (`<name>=_`), a PHP_SESSION_UPLOAD_PROGRESS field and a one-byte file part.
PHP's upload-progress hook then starts the session during request startup and, with display_errors AND
display_startup_errors both On, prints its warnings into the response:
  1. "Session ID is too long or contains illegal characters" (7.x: "The session id is too long or ...")
  2. "Failed to read session data: <handler>"
  3. "Failed to write session data (<handler>)"   <- only builds without the 2026-10-21 fix
Reproduced in tests/oracle_lab.py on 7.4 and 8.1-8.5 (mod_php, FPM, cli-server; PHP 7 defaults display_startup_errors
to Off, so a php.ini-less 7.x image stays silent) and on Ubuntu 24.04 php8.3 8.3.6-0maysync1 (3/3)
versus the backported 8.3.6-0ubuntu0.24.04.13 (2/3): the oracle tells a distro backport apart without a version change.
Silent (0/3) is NOT evidence either way: distro production php.ini hides startup errors, and use_strict_mode=1,
session.upload_progress.enabled=0, E_WARNING filtered out or a non-files handler (phpredis: 0/3 on 8.5.11 and 8.5.12)
suppress the warnings too. A 2/3 answer only counts as "patched" for the files handler, the one the lab validated."""
import re
import secrets

MARKERS = ("is too long or contains illegal characters",  # 8.x "Session ID is ...", 7.x "The session id is ..."
           "Failed to read session data",
           "Failed to write session data (")
HANDLER_RE = re.compile(r"Failed to read session data: ([A-Za-z0-9_]+)")
# Session cookie names seen on the endpoint are probed too: a custom session.name ignores PHPSESSID (lab: 0/3 -> 3/3).
SESSION_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]*(?:sess|sid)[A-Za-z0-9_.-]*)=", re.I)
MAX_NAMES = 4
VALIDATED_HANDLERS = {"files"}
PATHS = ("/index.php",)  # generic fallback candidate
MAX_POSTS = 2


def session_names(cookies):
    names = ["PHPSESSID"]
    for c in cookies:
        m = SESSION_NAME_RE.match(c)
        if m and m[1] not in names and len(names) < MAX_NAMES:
            names.append(m[1])
    return names


def build(names):
    """(content_type, cookie_header, body bytes). Random boundary/token so caches and WAF replays never match."""
    b = "----p2s" + secrets.token_hex(12)
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\np2s{secrets.token_hex(6)}\r\n"
            f"--{b}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"p2s.txt\"\r\nContent-Type: text/plain\r\n\r\n1\r\n"
            f"--{b}--\r\n")
    return f"multipart/form-data; boundary={b}", "; ".join(f"{n}=_" for n in names), body.encode()


def evaluate(body):
    """(result, markers_seen, session_handler) for a response body.
    VULNERABLE = all three warnings; PATCHED = read warnings shown, write warning absent (files handler);
    UNVALIDATED = the same 2/3 answer from another handler; PARTIAL / SILENT = no verdict."""
    seen = [m in body for m in MARKERS]
    m = HANDLER_RE.search(body)
    handler = m[1] if m else ""
    if all(seen):
        return "VULNERABLE", 3, handler
    if seen[0] and seen[1]:
        return ("PATCHED" if handler in VALIDATED_HANDLERS else "UNVALIDATED"), 2, handler
    return ("PARTIAL" if any(seen) else "SILENT"), sum(seen), handler


def is_decisive(result):
    return result in ("VULNERABLE", "PATCHED")
