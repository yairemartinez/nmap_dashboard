import os
from dotenv import load_dotenv

# Load .env file if present
load_dotenv()

# Base directory (this file is in app/)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Project root (nmap_dashboard/)
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

# Database path (used by db_utils and app)
DB_PATH = os.path.join(PROJECT_ROOT, "nmap_results.db")

# Upload folder for imported XML files
UPLOAD_FOLDER = os.path.join(PROJECT_ROOT, "scans", "imports")

# Logs
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
LOG_FILE = os.path.join(LOG_DIR, "nmap_dashboard.log")
EXPORT_LOG_FILE = os.path.join(LOG_DIR, "export_log")

# Flask security
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set!")
