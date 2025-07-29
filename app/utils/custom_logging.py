# app/utils/custom_logging.py

import os
import sys
import logging

# ----------------------------------------
# Setup Paths for Logging Directory & Files
# ----------------------------------------

LOG_DIR = os.path.join(os.path.dirname(__file__), "../../logs")
os.makedirs(LOG_DIR, exist_ok=True)

MAIN_LOG_FILE = os.path.join(LOG_DIR, "nmap_dashboard.log")
EXPORT_LOG_FILE = os.path.join(LOG_DIR, "export_log")
STDERR_LOG_FILE = os.path.join(LOG_DIR, "dashboard.err")

# -------------------------------
# Root Logger Configuration (Main)
# -------------------------------

logging.basicConfig(
    filename=MAIN_LOG_FILE,          # Main combined file log
    level=logging.INFO,
    format="%(asctime)s %(levelname)s:%(message)s"
)

# -----------------------------
# Stream Handlers (stdout/stderr)
# Used by Docker logs output
# -----------------------------

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.INFO)

stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.WARNING)

logging.getLogger().addHandler(stdout_handler)
logging.getLogger().addHandler(stderr_handler)

# --------------------------------------------------
# Additional File Handlers for Dashboard-style Output
# --------------------------------------------------

# Logs WARNING and above to dashboard.err
dashboard_err_handler = logging.FileHandler(STDERR_LOG_FILE)
dashboard_err_handler.setLevel(logging.WARNING)
dashboard_err_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logging.getLogger().addHandler(dashboard_err_handler)

# -------------------------------
# Export-specific Logger Setup
# -------------------------------

export_logger = logging.getLogger("export_logger")
export_logger.setLevel(logging.DEBUG)

fh = logging.FileHandler(EXPORT_LOG_FILE)
fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

# Remove existing file handlers to avoid duplication
for handler in export_logger.handlers[:]:
    if isinstance(handler, logging.FileHandler):
        export_logger.removeHandler(handler)

export_logger.addHandler(fh)

# Prevent logs from being duplicated to root logger
export_logger.propagate = False

# --------------------------------
# Suppress Noisy Third-Party Logs
# --------------------------------

logging.getLogger("weasyprint").setLevel(logging.WARNING)
logging.getLogger("fontTools").setLevel(logging.WARNING)
logging.getLogger("fontTools.subset").setLevel(logging.WARNING)
logging.getLogger("fontTools.ttLib").setLevel(logging.WARNING)
logging.getLogger("PIL.PngImagePlugin").setLevel(logging.WARNING)
