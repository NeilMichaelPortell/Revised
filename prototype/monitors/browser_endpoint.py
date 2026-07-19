"""
Browser Endpoint
================
A simple HTTP server that receives POST requests from the browser
extension. Uses Python's built-in http.server — no Flask required.

Runs in a daemon thread. A threading.Event signals when the server
is actually bound and accepting connections before main.py continues.
"""

import json
import threading
import time
import socket
import datetime
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from config import FLASK_HOST, FLASK_PORT, SENSITIVE_PATH_KEYWORDS
from core.logger import write_log


# ── URL sanitiser ─────────────────────────────────────────────
def _sanitize(raw_url: str) -> dict:
    """
    Privacy-preserving reduction of a URL to scheme + domain ONLY.

    The full URL, path, query string, fragment and any page title are
    deliberately discarded and NEVER stored. If the path matches a sensitive
    keyword the visit is dropped entirely (domain not retained either).
    """
    if not raw_url:
        return {}
    p      = urlparse(raw_url)
    domain = p.netloc.lower().split(":")[0]
    path   = p.path.lower()
    scheme = p.scheme.lower() or "https"
    for kw in SENSITIVE_PATH_KEYWORDS:
        if kw in path:
            # sensitive path: do not retain the domain either
            return {"scheme": scheme, "blocked": True, "reason": "sensitive_path"}
    # scheme + domain only — no path, query, fragment or original URL
    return {"scheme": scheme, "domain": domain}


def _parse_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


# ── Request handler ───────────────────────────────────────────
class _Handler(BaseHTTPRequestHandler):

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            data   = json.loads(body) if body else {}
        except Exception:
            self._respond(400, "Bad Request")
            return

        if self.path == "/visit":
            url = data.get("url", "")
            if not url:
                self._respond(400, "Missing url")
                return
            write_log("website_visited", _sanitize(url), "browser")
            self._respond(200, "ok")

        elif self.path == "/download":
            payload = {
                "filename"     : data.get("file_name") or data.get("filename", ""),
                "mime_type"    : data.get("mime_type", ""),
                "file_size"    : data.get("file_size", 0),
                "source_domain": _parse_domain(data.get("url", "")),
            }
            write_log("file_downloaded", payload, "browser")
            self._respond(200, "ok")

        else:
            self._respond(404, "Not Found")

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, "ok")
        else:
            self._respond(404, "Not Found")

    def do_OPTIONS(self):
        # CORS preflight — browser extensions sometimes send this first
        self.send_response(200)
        self._cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _respond(self, code: int, body: str):
        enc = body.encode()
        self.send_response(code)
        self._cors_headers()
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(enc)))
        self.end_headers()
        self.wfile.write(enc)

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, fmt, *args):
        # Silence request logs — pipeline prints its own messages
        pass


# ── Startup ───────────────────────────────────────────────────
_ready = threading.Event()


def start():
    """
    Bind the HTTP server, signal _ready, then serve forever.
    Call this in a daemon thread from main.py.
    """
    try:
        server = HTTPServer((FLASK_HOST, FLASK_PORT), _Handler)
        _ready.set()                        # signal: port is bound
        server.serve_forever()
    except OSError as e:
        print(f"[Browser] ✗  Could not bind port {FLASK_PORT}: {e}")
        print( "[Browser]    Close anything using that port and restart.")
        _ready.set()                        # unblock the waiter even on error


def start_and_wait(timeout: float = 10.0) -> bool:
    """
    Start the server in a daemon thread and block until it is ready
    (or timeout expires). Returns True if the server is listening.
    """
    # Check if something already owns the port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        if s.connect_ex((FLASK_HOST, FLASK_PORT)) == 0:
            print(f"[Browser] ⚠  Port {FLASK_PORT} already in use.")
            print( "[Browser]    Close the other process and restart.")
            return False

    t = threading.Thread(target=start, daemon=True)
    t.start()

    if _ready.wait(timeout=timeout):
        # Do a quick socket probe to confirm it's actually accepting connections
        time.sleep(0.1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            if s.connect_ex((FLASK_HOST, FLASK_PORT)) == 0:
                print(f"[Browser] ✓  Endpoint ready → http://{FLASK_HOST}:{FLASK_PORT}")
                return True

    print(f"[Browser] ✗  Server did not start within {timeout}s.")
    print( "[Browser]    Browser events will NOT be tracked.")
    return False
