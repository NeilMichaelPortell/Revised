import os
import time
from core.logger import write_log


DOWNLOADS_DIR = os.path.join(os.path.expanduser("~"), "Downloads")


def run(session):
    """
    Watch the Downloads folder for new files.
    Complements the browser extension — catches downloads from apps,
    file managers, and any browser without the extension installed.
    """
    seen = set()
    print(f"[FileMonitor] Watching {DOWNLOADS_DIR} for new files...")

    # Seed with files already present so we don't alert on old downloads
    try:
        for f in os.listdir(DOWNLOADS_DIR):
            seen.add(os.path.join(DOWNLOADS_DIR, f))
    except Exception:
        pass

    while True:
        try:
            for filename in os.listdir(DOWNLOADS_DIR):
                path = os.path.join(DOWNLOADS_DIR, filename)

                if path in seen:
                    continue
                seen.add(path)

                data = {
                    "filename" : filename,
                    "path"     : path,
                    "size_bytes": os.path.getsize(path) if os.path.exists(path) else 0,
                }

                write_log("file_downloaded", data, "filesystem")

        except Exception:
            pass

        time.sleep(5)
