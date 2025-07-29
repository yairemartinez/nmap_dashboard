# archive_imports.py

import os
import zipfile
from datetime import datetime
import logging

# ✅ Resolve project base path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
IMPORTS_DIR = os.path.join(BASE_DIR, "scans", "imports")
ARCHIVE_DIR = os.path.join(BASE_DIR, "archive", "imports_backup")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "imports_archive.log")

DAYS_OLD = 0  # Archive files older than this (in days)

def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s"
    )

def archive_old_imports():
    now = datetime.now()

    if not os.path.exists(IMPORTS_DIR):
        os.makedirs(IMPORTS_DIR)
        logging.warning(f"Created missing IMPORTS_DIR: {IMPORTS_DIR}")
        return

    os.makedirs(ARCHIVE_DIR, exist_ok=True)

    for filename in os.listdir(IMPORTS_DIR):
        if not filename.endswith(".xml"):
            continue

        file_path = os.path.join(IMPORTS_DIR, filename)
        file_time = datetime.fromtimestamp(os.path.getmtime(file_path))

        if (now - file_time).days >= DAYS_OLD:
            zip_filename = os.path.join(ARCHIVE_DIR, f"{filename}.zip")

            if os.path.exists(zip_filename):
                logging.info(f"Archive already exists for {filename}, skipping.")
                continue

            try:
                with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    zipf.write(file_path, arcname=filename)

                os.remove(file_path)
                logging.info(f"📦 Archived and removed import: {filename}")
                print(f"📦 Archived and removed import: {filename}")

            except Exception as e:
                logging.error(f"Failed to archive {filename}: {e}")
                print(f"❌ Failed to archive {filename}: {e}")

if __name__ == "__main__":
    setup_logging()
    archive_old_imports()


