"""Mock PHP-ish HTTP servers for testing. Binds 0.0.0.0 so every 127.x.y.z address answers (large-subnet tests).
usage: python3 mock_servers.py [variant]   variant 'b' = after-patch state of port 8101/8104 (for diff tests)"""
import http.server, socketserver, sys, threading, time

variant = sys.argv[1] if len(sys.argv) > 1 else "a"
cfg = {
    8101: {"X-Powered-By": "PHP/8.3.12" if variant == "a" else "PHP/8.3.36"},
    8102: {"X-Powered-By": "PHP/8.3.36"},
    8103: {"Server": "Apache/2.4.58 (Ubuntu)", "X-Powered-By": "PHP/8.3.6-1ubuntu0.5"},
    8104: {"X-Powered-By": "PHP/7.4.33" if variant == "a" else "PHP/8.4.27"},
    8105: {"Set-Cookie": "PHPSESSID=abc; path=/"},
    8106: {"Server": "nginx"},
    8107: {"X-Powered-By": "PHP/8.5.11"},
    8108: {"X-Powered-By": "PHP/8.4.<script>alert(1)</script>", "Server": "=cmd|' /C calc'!A0"},  # hostile banners
}
REDIRECT = {8110: ("http://127.0.0.1:8109/", "PHP/8.1.0")}  # 302 to a non-HTTP port (review #4)
# --oracle: PHP that displays request-startup warnings. 8111 pre-fix (version hidden), 8112 Ubuntu backport (fixed).
W = "<br />\n<b>Warning</b>:  PHP Request Startup: "
ORACLE_WARNINGS = [W + "Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9 ...<br />\n",
                   W + "Failed to read session data: files (path: /var/lib/php/sessions)<br />\n",
                   W + "Failed to write session data (files). Please verify that the current setting of session.save_path is correct<br />\n"]
ORACLE = {8111: ({"Set-Cookie": "PHPSESSID=abc; path=/"}, 3),
          8112: ({"Server": "Apache/2.4.58 (Ubuntu)", "X-Powered-By": "PHP/8.3.6"}, 2)}
cfg.update({p: h for p, (h, _) in ORACLE.items()})


# --deep / link discovery: path-aware sites. route -> (status, headers, body); POST warnings only on PHP_POST paths.
SITES = {
    8113: {"*": (200, {}, "<html><div id=app></div><script src=/app.js></script></html>")},  # SPA: 200 for every path
    8114: {"/": (200, {}, "<html>blog home</html>"),  # WordPress with stripped headers and a static-looking home page
           "/wp-login.php": (200, {}, '<form name="loginform"><input id="user_login" name="log"><input name="wp-submit"></form>')},
    8115: {"/": (200, {}, '<html><a href="portal/search.php?q=1">search</a></html>'),  # static front, PHP behind a link
           "/portal/search.php": (200, {}, "results")},
}
PHP_POST = {8115: {"/portal/search.php"}}


def mk_site(port):
    routes = SITES[port]
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        def _send(s, status, headers, body):
            s.send_response(status)
            for k, v in headers.items():
                s.send_header(k, v)
            s.end_headers()
            s.wfile.write(body.encode())
        def do_GET(s):
            path = s.path.split("?")[0]
            s._send(*(routes.get(path) or routes.get("*") or (404, {}, "not found")))
        def do_POST(s):
            body = s.rfile.read(int(s.headers.get("Content-Length", 0))).decode("latin-1")
            hit = s.path in PHP_POST.get(port, ()) and "=_" in s.headers.get("Cookie", "") and "PHP_SESSION_UPLOAD_PROGRESS" in body
            s._send(200, {}, ("".join(ORACLE_WARNINGS) if hit else "") + "ok")
        def log_message(*a): pass
    return H


def mk(h, warnings=0):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        def do_GET(s):
            s.send_response(200)
            for k, v in h.items():
                try:
                    s.send_header(k, v)
                except Exception:
                    pass
            s.end_headers()
            s.wfile.write(b"<html>wp-content hello</html>")
        def do_POST(s):  # real PHP only warns for an invalid session id + upload-progress field + a file part
            body = s.rfile.read(int(s.headers.get("Content-Length", 0))).decode("latin-1")
            hit = warnings and "=_" in s.headers.get("Cookie", "") and "PHP_SESSION_UPLOAD_PROGRESS" in body and "filename=" in body
            s.send_response(200)
            s.end_headers()
            s.wfile.write(("".join(ORACLE_WARNINGS[:warnings]) if hit else "").encode() + b"hello")
        def log_message(*a): pass
    return H


class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    request_queue_size = 1024
    allow_reuse_address = True


def mk_redirect(loc, xpb):
    class R(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        def do_GET(s):
            s.send_response(302); s.send_header("Location", loc); s.send_header("X-Powered-By", xpb); s.end_headers()
        def log_message(*a): pass
    return R


for p, h in cfg.items():
    threading.Thread(target=S(("0.0.0.0", p), mk(h, ORACLE.get(p, (None, 0))[1])).serve_forever, daemon=True).start()
for p in SITES:
    threading.Thread(target=S(("0.0.0.0", p), mk_site(p)).serve_forever, daemon=True).start()
for p, (loc, xpb) in REDIRECT.items():
    threading.Thread(target=S(("0.0.0.0", p), mk_redirect(loc, xpb)).serve_forever, daemon=True).start()
# a port that accepts TCP but is not HTTP
def raw():
    import socket
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 8109)); s.listen(512)
    while True:
        c, _ = s.accept(); c.sendall(b"SSH-2.0-fake\r\n"); c.close()
threading.Thread(target=raw, daemon=True).start()


def fastcgi():  # 8116: exposed PHP-FPM; answers GET_VALUES and a missing-script request like php-fpm 8.3.12 would
    import socket, struct
    rec = lambda t, rid, c: struct.pack(">BBHHBB", 1, t, rid, len(c), 0, 0) + c
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 8116)); s.listen(64)
    while True:
        c, _ = s.accept()
        try:
            c.settimeout(2)
            head = c.recv(8)
            if len(head) == 8 and head[0] == 1 and head[1] == 9:
                c.sendall(rec(10, 0, b"\x0f\x01FCGI_MPXS_CONNS0"))
            elif len(head) == 8 and head[0] == 1 and head[1] == 1:
                c.sendall(rec(6, 1, b"Status: 404 Not Found\r\nX-Powered-By: PHP/8.3.12\r\nContent-type: text/html\r\n\r\nFile not found.\n")
                          + rec(7, 1, b"Primary script unknown") + rec(3, 1, b"\0" * 8))
        except OSError:
            pass
        finally:
            c.close()
threading.Thread(target=fastcgi, daemon=True).start()
print("mock ready", flush=True)
time.sleep(int(sys.argv[2]) if len(sys.argv) > 2 else 300)
