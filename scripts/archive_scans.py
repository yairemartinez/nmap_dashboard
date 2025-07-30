# archive_scans.py

import os
import zipfile
import logging
from datetime import datetime

# ✅ Base path (project root)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCAN_DIR = os.path.join(BASE_DIR, "scans")
ARCHIVE_DIR = os.path.join(BASE_DIR, "archive")
DAYS_OLD = 0  # Archive files older than this (in days)

# Setup logging
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "archive.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)

def archive_old_scans():
    now = datetime.now()
    os.makedirs(ARCHIVE_DIR, exist_ok=True)

    if not os.path.exists(SCAN_DIR):
        os.makedirs(SCAN_DIR)
        logging.warning(f"Created missing directory: {SCAN_DIR}")
        print(f"📁 Created missing directory: {SCAN_DIR}")
        return

    for filename in os.listdir(SCAN_DIR):
        file_path = os.path.join(SCAN_DIR, filename)

        if not os.path.isfile(file_path):
            continue

        file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
        age_days = (now - file_time).days

        if age_days < DAYS_OLD:
            continue

        if filename.endswith((".xml", ".txt")):
            zip_filename = os.path.join(ARCHIVE_DIR, f"{filename}.zip")
            try:
                with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    zipf.write(file_path, arcname=filename)
                os.remove(file_path)
                logging.info(f"📦 Archived and removed: {filename}")
                print(f"📦 Archived and removed: {filename}")
            except Exception as e:
                logging.error(f"❌ Failed to archive {filename}: {e}")
                print(f"❌ Failed to archive {filename}: {e}")

if __name__ == "__main__":
    archive_old_scans()

