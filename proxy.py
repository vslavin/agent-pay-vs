#!/usr/bin/env python3
"""
Agent Pay — tiny reverse proxy so the app AND Keycloak share one public
(ngrok) domain. Python 3 stdlib only.

    ngrok https://<domain>  →  this proxy :8000
        /realms/*, /resources/*   →  Keycloak   localhost:8080
        /admin*, /internal*       →  403 (admin console / Keycloak→app hook stay local)
        everything else           →  demo app   localhost:3000

The original Host header is passed through (plus X-Forwarded-*), so Keycloak
(--proxy-headers=xforwarded) and the app both build public URLs.
"""

import http.client
import http.server
import os
import socketserver
import sys

PORT     = int(os.environ.get("PROXY_PORT", "8000"))
KEYCLOAK = ("127.0.0.1", 8080)
APP      = ("127.0.0.1", 3000)
KC_PREFIXES = ("/realms/", "/resources/")
BLOCKED     = ("/admin", "/internal")

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade"}


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stdout.write("  %s %s\n" % (self.address_string(), fmt % args))
        sys.stdout.flush()

    def _route(self):
        path = self.path.split("?", 1)[0]
        if path.startswith(BLOCKED):
            return None
        return KEYCLOAK if path.startswith(KC_PREFIXES) else APP

    def _proxy(self):
        upstream = self._route()
        if upstream is None:
            body = b"Not available on the public address.\n"
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None

        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")
        headers["Host"] = host
        headers["X-Forwarded-Host"] = host
        headers["X-Forwarded-Proto"] = self.headers.get("X-Forwarded-Proto", "https")
        headers["X-Forwarded-Port"] = "443" if headers["X-Forwarded-Proto"] == "https" else "80"
        headers.setdefault("X-Forwarded-For", self.client_address[0])

        try:
            conn = http.client.HTTPConnection(*upstream, timeout=60)
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
        except OSError as e:
            msg = f"Upstream {upstream[0]}:{upstream[1]} unavailable: {e}\n".encode()
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return

        self.send_response(resp.status, resp.reason)
        for k, v in resp.getheaders():           # keeps repeated Set-Cookie headers
            if k.lower() not in HOP_BY_HOP and k.lower() != "content-length":
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        conn.close()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _proxy


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    print(f"Agent Pay proxy on :{PORT}  (/realms,/resources → :8080, /admin blocked, rest → :3000)")
    sys.stdout.flush()
    Server(("127.0.0.1", PORT), Proxy).serve_forever()
