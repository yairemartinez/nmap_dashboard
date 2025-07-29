# app/routes/core.py
# ---------------------
# Core routes: homepage, delete/undo, upload, cleanup
# ---------------------

from flask import Blueprint, render_template, request, redirect, flash, session, url_for
from werkzeug.utils import secure_filename
from app.utils.db_utils import get_scan_summaries, delete_orphaned_results
from app.utils.scanner_presets import SCAN_CATEGORIES
import sys
import os, sqlite3, subprocess
from datetime import datetime
import re
import logging
from app.utils import custom_logging

#  Define core blueprint
bp = Blueprint("core", __name__)

# ---------------------
#  Route: Dashboard Home
# ---------------------
@bp.route("/")
def index():
    """
    Dashboard index page, optionally filtered by scan_type or timestamp.
    """
    scan_type = request.args.get("scan_type")
    timestamp = request.args.get("timestamp")

    #  Get filtered or all scan summaries
    scans = get_scan_summaries(scan_type=scan_type, timestamp=timestamp)

    #  Render main dashboard view
    return render_template("index.html", scans=scans, scan_categories=SCAN_CATEGORIES)


# ---------------------
#  Route: Delete a Scan
# ---------------------
@bp.route("/delete/<int:session_id>", methods=["POST"])
def delete_scan(session_id):
    """
    Delete a scan session and store it in session for undo capability.
    """
    conn = sqlite3.connect("nmap_results.db")
    cursor = conn.cursor()

    #  Save session and results before deletion
    cursor.execute("SELECT timestamp, scan_type, xml_path, log_path FROM scan_sessions WHERE id = ?", (session_id,))
    session_data = cursor.fetchone()

    cursor.execute("SELECT * FROM scan_results WHERE session_id = ?", (session_id,))
    results_data = cursor.fetchall()

    #  Store deleted data in Flask session for undo
    session["last_deleted"] = {"session": session_data, "results": results_data}

    #  Delete from database
    cursor.execute("DELETE FROM scan_sessions WHERE id = ?", (session_id,))
    conn.commit()
    conn.close()

    flash("Scan deleted. You can undo this action.", "success")
    return redirect(url_for("core.index"))


# ---------------------
#  Route: Undo Deletion
# ---------------------
@bp.route("/undo_delete", methods=["POST"])
def undo_delete():
    """
    Restore the last deleted scan from session memory.
    """
    deleted = session.get("last_deleted")
    if not deleted:
        flash("No scan to undo.", "warning")
        return redirect(url_for("core.index"))

    try:
        conn = sqlite3.connect("nmap_results.db")
        cursor = conn.cursor()

        #  Re-insert session info
        cursor.execute("""
            INSERT INTO scan_sessions (timestamp, scan_type, xml_path, log_path)
            VALUES (?, ?, ?, ?)
        """, deleted["session"])
        new_session_id = cursor.lastrowid

        #  Re-insert results under new session_id
        updated_results = [(new_session_id,) + row[2:] for row in deleted["results"]]
        cursor.executemany("""
            INSERT INTO scan_results (
                session_id, ip, hostname, mac_addr, vendor,
                protocol, port, state, service, product,
                version, os, cpe, uptime, last_boot, script, risk_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, updated_results)

        conn.commit()
        conn.close()

        #  Clear undo memory
        session.pop("last_deleted")
        flash("Scan restored successfully!", "info")

    except Exception as e:
        flash(f"❌ Error restoring scan: {e}", "danger")

    return redirect(url_for("core.index"))


# ---------------------
#  Route: Preview Deleted Scan
# ---------------------
@bp.route("/undo_preview")
def undo_preview():
    """
    Preview details of the last deleted scan session.
    """
    deleted = session.get("last_deleted")
    if not deleted:
        flash("No scan to preview.", "warning")
        return redirect(url_for("core.index"))

    #  Render preview of deleted scan session + results
    return render_template("undo_preview.html", session=deleted["session"], results=deleted["results"])


# ---------------------
#  Route: Cleanup Orphaned Results
# ---------------------
@bp.route("/cleanup_orphans", methods=["POST"])
def cleanup_orphans():
    """
    Deletes results that belong to non-existent sessions.
    """
    deleted_count = delete_orphaned_results()
    if deleted_count == -1:
        flash("Database is locked, try again later.", "warning")
    else:
        flash(f"Cleaned up {deleted_count} orphaned entries.", "info")
    return redirect(url_for("core.index"))


# ---------------------
#  Route: Upload + Import XML
# ---------------------
@bp.route("/upload", methods=["POST"])
def upload_xml():
    """
    Uploads and imports an Nmap XML scan.
    """
    uploaded = request.files.get("xmlfile")

    # ❌ Validate file
    if not uploaded or not uploaded.filename.lower().endswith(".xml"):
        flash("Please select a valid XML file.", "warning")
        return redirect(url_for("core.index"))

    #  Generate unique filename and save
    safe_name = secure_filename(uploaded.filename)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    saved_name = f"{os.path.splitext(safe_name)[0]}_{timestamp}.xml"

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    upload_dir = os.path.join(base_dir, "scans", "imports")
    os.makedirs(upload_dir, exist_ok=True)

    save_path = os.path.join(upload_dir, saved_name)
    uploaded.save(save_path)

    #  Build path for corresponding log file
    log_name = f"log_{os.path.splitext(saved_name)[0].replace('scan_', '')}.txt"
    log_path = os.path.join(upload_dir, log_name)

    #  Call parser script via subprocess using current virtualenv
    venv_python = sys.executable
    parse_script = os.path.join(base_dir, "app", "utils", "parse2_nmap.py")

    try:
        result = subprocess.run(
            [venv_python, parse_script, save_path, log_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "PYTHONPATH": base_dir}
        )

        #  Extract session ID from parser output
        matches = re.findall(r"\b\d+\b", result.stdout)
        if not matches:
            logging.warning(f"⚠️  Parser stdout:\n{result.stdout}")
            logging.warning(f"⚠️  Parser stderr:\n{result.stderr}")
            flash("Import succeeded, but session ID was not returned properly.", "warning")
            return redirect(url_for("core.index"))

        session_id = int(matches[-1])  # use last number found

    except subprocess.CalledProcessError as e:
        logging.error(f"❌ Failed to import scan: {e.stderr}")
        flash("Import failed. Check server logs for details.", "danger")
        return redirect(url_for("core.index"))

    #  Track upload in uploads table
    db_path = os.path.join(base_dir, "nmap_results.db")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO uploads (filename, upload_time, session_id) VALUES (?, ?, ?)",
        (saved_name, datetime.now().isoformat(), session_id)
    )
    conn.commit()
    conn.close()

    flash(f"Imported XML as session #{session_id}", "success")
    return redirect(url_for("scans.scan_detail", session_id=session_id))

