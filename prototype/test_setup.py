"""
test_setup.py  —  run this BEFORE main.py to confirm everything works.
Usage:  python test_setup.py
"""

import sys
import subprocess
import urllib.request
import json
import time
import threading
import os

print("\n" + "="*60)
print("  CYBER MONITOR — SETUP TEST")
print("="*60)

passed = 0
failed = 0

def ok(msg):
    global passed
    passed += 1
    print(f"  ✓  {msg}")

def fail(msg, fix=""):
    global failed
    failed += 1
    print(f"  ✗  {msg}")
    if fix:
        print(f"     FIX: {fix}")

# ── 1. Python packages ────────────────────────────────────────
print("\n[ 1 ] Python packages")
for pkg, import_name in [
    ("psutil",      "psutil"),
    ("win32gui",    "win32gui"),
    ("wmi",         "wmi"),
]:
    try:
        __import__(import_name)
        ok(pkg)
    except ImportError:
        fail(pkg, f"pip install {pkg if pkg != 'win32gui' else 'pywin32'}")

# ── 2. Ollama reachable ───────────────────────────────────────
print("\n[ 2 ] Ollama")
try:
    r = subprocess.run(
        ["ollama", "list"],
        capture_output=True, text=True, timeout=5,
        creationflags=0x08000000 if sys.platform=="win32" else 0,
    )
    if r.returncode == 0:
        lines = [l for l in r.stdout.strip().splitlines()[1:] if l.strip()]
        if lines:
            ok(f"Ollama running — {len(lines)} model(s) installed:")
            for l in lines:
                print(f"       {l.split()[0]}")
        else:
            fail("Ollama running but no models installed",
                 "ollama pull llama3:latest")
    else:
        fail("Ollama not responding", "run: ollama serve")
except FileNotFoundError:
    fail("Ollama not found in PATH", "install from https://ollama.com")
except subprocess.TimeoutExpired:
    fail("Ollama timed out", "run: ollama serve")

# ── 3. Flask endpoint ─────────────────────────────────────────
print("\n[ 3 ] Browser endpoint (Flask)")

# Check port free
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.settimeout(1)
    port_busy = s.connect_ex(("127.0.0.1", 5000)) == 0

if port_busy:
    fail("Port 5000 already in use",
         "another process is using port 5000 — close it or change FLASK_PORT in config.py")
else:
    # Test built-in HTTP server (no Flask needed)
    try:
        from http.server import HTTPServer, BaseHTTPRequestHandler

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            def log_message(self, *a): pass

        ready = threading.Event()
        def _run():
            s = HTTPServer(("127.0.0.1", 5000), _H)
            ready.set()
            s.handle_request()   # serve one request then stop

        threading.Thread(target=_run, daemon=True).start()
        ready.wait(timeout=3)
        time.sleep(0.1)

        with urllib.request.urlopen("http://127.0.0.1:5000/health", timeout=3) as resp:
            if resp.read() == b"ok":
                ok("Browser endpoint (built-in HTTP server) starts correctly")
            else:
                fail("HTTP server responded but with unexpected content")
    except Exception as e:
        fail(f"HTTP server test failed: {e}")

# ── 4. outputs/ folder writable ──────────────────────────────
print("\n[ 4 ] Output folder")
try:
    os.makedirs("outputs", exist_ok=True)
    test_file = os.path.join("outputs", "_test.tmp")
    with open(test_file, "w") as f:
        f.write("test")
    os.remove(test_file)
    ok("outputs/ folder is writable")
except Exception as e:
    fail(f"Cannot write to outputs/: {e}",
         "check folder permissions")

# ── 5. Browser extension ──────────────────────────────────────
print("\n[ 5 ] Browser extension")
ext_dir = os.path.join(os.path.dirname(__file__), "..", "webTracker")
if os.path.exists(os.path.join(ext_dir, "manifest.json")):
    ok("webTracker extension folder found")
    print("     To install: Chrome → Extensions → Load unpacked → select webTracker/")
else:
    fail("webTracker folder not found next to Cyber-Monitor/",
         "make sure webTracker/ is in the same parent folder as Cyber-Monitor/")

# ── Summary ───────────────────────────────────────────────────
print("\n" + "="*60)
print(f"  {passed} passed   {failed} failed")
if failed == 0:
    print("  ✓  Everything looks good — run: python main.py")
else:
    print("  ✗  Fix the issues above before running main.py")
print("="*60 + "\n")
