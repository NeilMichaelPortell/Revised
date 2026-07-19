import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Files ─────────────────────────────────────────────────────
LOG_FILE     = os.path.join(BASE_DIR, "outputs", "usage_logs.jsonl")
ALERT_TXT    = os.path.join(BASE_DIR, "outputs", "security_alerts.txt")
ALERT_JSON   = os.path.join(BASE_DIR, "outputs", "security_alerts.jsonl")
SUMMARY_FILE = os.path.join(BASE_DIR, "outputs", "session_summary.json")
DATASET_FILE = os.path.join(BASE_DIR, "outputs", "research_dataset.jsonl")

# ── Timing ────────────────────────────────────────────────────
SUMMARY_INTERVAL  = 60    # seconds between rolling summary writes
COOLDOWN_SECONDS  = 45    # min gap before re-alerting on the same threat type

# ── Ollama ────────────────────────────────────────────────────
OLLAMA_MODEL   = None         # set at startup; all five models are equal choices
OLLAMA_TIMEOUT = 120          # generous headroom for first cold load / larger models

# ── Flask browser endpoint ────────────────────────────────────
# Runs as a NORMAL-USER subprocess so Chrome/Edge can always
# reach it even when the main process is elevated (admin).
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000

# ── Risk weights ──────────────────────────────────────────────
RISK_WEIGHTS = {
    "http_browsing"          : 1,
    "unknown_source_download": 2,
    "risky_download"         : 3,
    "torrent_download"       : 4,
    "suspicious_process"     : 5,
    "usb_connected"          : 2,
    "login_failed"           : 1,
    "defender_disabled"      : 10,
    "scheduled_task_created" : 4,
    "scheduled_task_updated" : 3,
    "service_start_changed"  : 3,
    "security_log_cleared"   : 8,
    "audit_policy_changed"   : 5,
    "public_network"         : 2,
}

# ── Threat lists ──────────────────────────────────────────────
TRUSTED_DOMAINS = [
    "microsoft.com", "google.com", "github.com",
    "mozilla.org",   "adobe.com",  "apple.com",
    "amazon.com",    "cloudflare.com",
]

RISKY_EXTENSIONS = [
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs",
    ".js",  ".jar", ".scr", ".com", ".pif", ".reg",
    ".hta", ".wsf", ".torrent",
]

SUSPICIOUS_KEYWORDS = [
    "torrent", "utorrent", "bittorrent", "qbittorrent",
    "crack", "keygen", "patch", "loader", "bypass",
    "mimikatz", "metasploit", "cobalt", "empire",
    "netcat", "ncat", "nc.exe", "psexec",
    "darkcomet", "njrat", "quasar", "asyncrat",
    "xmrig", "miner", "ransomware",
]

KNOWN_SAFE_PROCESSES = {
    "explorer.exe", "svchost.exe", "csrss.exe", "winlogon.exe",
    "lsass.exe",    "services.exe","smss.exe",  "wininit.exe",
    "taskhostw.exe","dwm.exe",     "conhost.exe","dllhost.exe",
    "searchindexer.exe","spoolsv.exe","audiodg.exe",
    "python.exe",   "pythonw.exe", "code.exe",  "node.exe",
}

SENSITIVE_PATH_KEYWORDS = [
    "login", "signin", "account", "password", "auth",
    "token", "session", "private", "bank", "wallet", "payment",
]
