# app/routes/scans.py
# ---------------------
#  View, tag, export, and analyze individual scan sessions
# ---------------------

from flask import Blueprint, render_template, request, redirect, flash, url_for, Response, make_response, jsonify
from app.utils.db_utils import (
    get_scan_details, get_scan_summary, compute_diff, get_tags, set_tag,
    get_scan_summaries, get_hosts_and_ports
)
from app.utils.risk_utils import compute_host_risk_and_reasons, compute_row_risk_score
from weasyprint import HTML, logger as weasy_logger
from app.config import DB_PATH
from app.utils.tag_suggestions import suggest_tags
from app.utils.custom_logging import export_logger
import sqlite3
import csv
import os
import logging
from logging.handlers import RotatingFileHandler
from io import StringIO
from datetime import datetime 

bp = Blueprint("scans", __name__)

# ---------------------
#  Scan Detail View
# ---------------------
@bp.route("/scan/<int:session_id>")
def scan_detail(session_id):
    """
    Show detailed results of a scan session, with optional filters and tag analysis.
    """
    # GET filters
    ip_filter = request.args.get("ip")
    port_filter = request.args.get("port")
    service_filter = request.args.get("service")
    device_tag_filter = request.args.get("device_tag", "").lower()
    service_tag_filter = request.args.get("service_tag", "").lower()

    # Get raw scan result rows and scan summary
    details = get_scan_details(session_id, ip_filter, port_filter, service_filter)
    summary = get_scan_summary(session_id)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Fetch highest risk host
    cursor.execute("""
        SELECT ip, SUM(risk_score) as total_risk
        FROM scan_results
        WHERE session_id = ?
        GROUP BY ip
        ORDER BY total_risk DESC
        LIMIT 1
    """, (session_id,))
    row = cursor.fetchone()
    highest_ip, highest_score = row if row else (None, None)

    # Per-host risk scores
    cursor.execute("""
        SELECT ip, SUM(risk_score)
        FROM scan_results
        WHERE session_id = ?
        GROUP BY ip
    """, (session_id,))
    risk_by_host = dict(cursor.fetchall())

    # Risk breakdown
    cursor.execute("""
        SELECT ip, port, service, risk_score
        FROM scan_results
        WHERE session_id = ? AND state = 'open'
    """, (session_id,))
    rows = cursor.fetchall()
    risk_reasons_by_host = {}
    for ip, port, service, score in rows:
        reason = f"Port {port}, Service '{service}', Score: {score}"
        risk_reasons_by_host.setdefault(ip, []).append(reason)

    # Load global tags
    cursor.execute("SELECT ip, device_tag, service_tag FROM global_tags")
    global_tags_raw = cursor.fetchall()
    global_tags = {row[0]: {"device": row[1], "service": row[2]} for row in global_tags_raw}

    # Load trusted status from user_network (normalize MACs to match how they're stored)
    cursor.execute("SELECT ip, mac_addr, status FROM user_network")
    trusted_hosts_raw = cursor.fetchall()
    trusted_status = {
        (ip, mac.upper().replace(":", "").replace("-", "")): status
        for ip, mac, status in trusted_hosts_raw
    }

    # Build status map by (ip, normalized_mac) from current scan results
    status_by_ip_mac = {}
    for row in details:
        ip = row[0]
        mac_addr_raw = row[10] or ""
        mac_addr = mac_addr_raw.upper().replace(":", "").replace("-", "").strip()

        status = trusted_status.get((ip, mac_addr))

        if status:
            status_by_ip_mac[(ip, mac_addr)] = status


    # Tag aggregation
    tags = {}
    all_device_tags = set()
    all_service_tags = set()
    for row in details:
        ip, _, port, _, service, _, _, os_match, *_rest, risk_score = row
        mac_vendor = row[11]
        global_tag = global_tags.get(ip, {"device": "", "service": ""})
        suggested_device, suggested_service = suggest_tags(ip, port, service, mac_vendor, os_match)

        tags[ip] = {
            "global": global_tag,
            "suggested": {
                "device": suggested_device,
                "service": suggested_service
            }
        }

        if global_tag["device"]:
            all_device_tags.add(global_tag["device"])
        if global_tag["service"]:
            all_service_tags.add(global_tag["service"])

    # Filter by tags
    if device_tag_filter or service_tag_filter:
        filtered_details = []
        for row in details:
            ip = row[0]
            tag = tags.get(ip, {})
            device_tag = tag.get("global", {}).get("device", "").lower()
            service_tag = tag.get("global", {}).get("service", "").lower()
            if device_tag_filter and device_tag_filter not in device_tag:
                continue
            if service_tag_filter and service_tag_filter not in service_tag:
                continue
            filtered_details.append(row)
        details = filtered_details

    # Metadata
    cursor.execute("SELECT timestamp, scan_type FROM scan_sessions WHERE id = ?", (session_id,))
    row = cursor.fetchone()
    conn.close()
    timestamp, scan_type = row if row else ("Unknown", "Unknown")

    # Chart data
    port_counts = {}
    service_counts = {}
    for row in details:
        port = row[2]
        service = row[4]
        port_counts[port] = port_counts.get(port, 0) + 1
        service_counts[service] = service_counts.get(service, 0) + 1

    return render_template("scan_detail.html",
        session_id=session_id,
        timestamp=timestamp,
        scan_type=scan_type,
        details=details,
        summary=summary,
        filters={
            "ip": ip_filter,
            "port": port_filter,
            "service": service_filter,
            "device_tag": request.args.get("device_tag", ""),
            "service_tag": request.args.get("service_tag", "")
        },
        risk_by_host=risk_by_host,
        risk_reasons_by_host=risk_reasons_by_host,
        highest_ip=highest_ip,
        highest_score=highest_score,
        tags=tags,
        port_labels=[str(p) for p in port_counts.keys()],
        port_counts=list(port_counts.values()),
        service_labels=list(service_counts.keys()),
        service_counts=list(service_counts.values()),
        all_device_tags=sorted(all_device_tags),
        all_service_tags=sorted(all_service_tags),
        trusted_status=status_by_ip_mac
    )

# ---------------------
# Apply Suggested Tags
# ---------------------
@bp.route("/apply_suggested_tags/<int:session_id>", methods=["POST"])
def apply_suggested_tags(session_id):
    ip = request.form.get("ip")
    mac = request.form.get("mac", "").strip()
    suggested_device = request.form.get("suggested_device")
    suggested_service = request.form.get("suggested_service")

    # Fallback: look up MAC from scan_results if not provided
    if not mac:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT mac_addr FROM scan_results
            WHERE session_id = ? AND ip = ? AND mac_addr IS NOT NULL AND mac_addr != ''
            ORDER BY id DESC LIMIT 1
        """, (session_id, ip))
        row = cursor.fetchone()
        mac = row[0] if row else ""
        conn.close()

    if suggested_device:
        set_tag(session_id, ip, mac, "device", suggested_device)
    if suggested_service:
        set_tag(session_id, ip, mac, "service", suggested_service)

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({
            "success": True,
            "ip": ip,
            "mac": mac,
            "device_tag": suggested_device,
            "service_tag": suggested_service,
            "message": f"Tags updated for {ip} ({mac})"
        })

    flash(f"Tags updated for {ip} ({mac})", "success")
    return redirect(url_for("scans.scan_detail", session_id=session_id))

# ---------------------
#  Update Tags
# ---------------------
@bp.route("/scan/<int:session_id>/set_tags", methods=["POST"])
def set_tags_route(session_id):
    """
    Update device/service tags for a specific IP and MAC in a scan session.
    Falls back to lookup MAC from scan_results if not provided.
    """
    ip = request.form.get("ip")
    mac = request.form.get("mac", "").strip()
    device_tag = request.form.get("device_tag")
    service_tag = request.form.get("service_tag")

    if not ip:
        flash("❌ IP address is required", "danger")
        return redirect(url_for("scans.scan_detail", session_id=session_id))

    # Fallback: look up MAC from scan_results if not provided
    if not mac:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT mac_addr FROM scan_results
            WHERE session_id = ? AND ip = ? AND mac_addr IS NOT NULL AND mac_addr != ''
            ORDER BY id DESC LIMIT 1
        """, (session_id, ip))
        row = cursor.fetchone()
        mac = row[0] if row else ""
        conn.close()

    if device_tag:
        set_tag(session_id, ip, mac, "device", device_tag)
    if service_tag:
        set_tag(session_id, ip, mac, "service", service_tag)

    flash(f"Tags updated for {ip} ({mac or 'N/A'})", "success")
    return redirect(url_for("scans.scan_detail", session_id=session_id))


# ---------------------
#  Export to PDF
# ---------------------
@bp.route("/export/<int:session_id>.pdf")
def export_pdf(session_id):
    export_logger.info(f"Starting export for session {session_id}")

    try:
        #  Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        filename_ts = datetime.now().strftime("%Y%m%d-%H%M")

        #  Query scan result rows with global tags and risk score
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    r.ip, r.hostname, r.mac_addr, r.vendor, r.protocol, r.port,
                    r.state, r.service, r.product, r.version, r.os, r.cpe,
                    r.uptime, r.last_boot, r.script,
                    COALESCE(gt.device_tag, '') AS device_tag,
                    COALESCE(gt.service_tag, '') AS service_tag,
                    COALESCE(r.risk_score, 0) as risk_score
                FROM scan_results r
                LEFT JOIN global_tags gt ON r.ip = gt.ip
                WHERE r.session_id = ?
                ORDER BY r.ip, r.port
            """, (session_id,))
            rows = cursor.fetchall()

        export_logger.info(f"Retrieved {len(rows)} rows for session {session_id}")

        #  Render HTML with timestamp for PDF
        rendered = render_template(
            "export_pdf.html",
            session_id=session_id,
            rows=rows,
            datetime_now=timestamp
        )
        export_logger.info("HTML rendered for PDF export")

        #  Generate PDF
        pdf = HTML(string=rendered).write_pdf()
        export_logger.info("✅ PDF generation complete")

        #  Serve PDF with timestamped filename
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = (
            f'attachment; filename=scan_{session_id}_{filename_ts}.pdf'
        )
        return response

    except Exception as e:
        export_logger.exception(f"❌ PDF export failed for session {session_id}: {e}")
        flash("An error occurred while exporting the PDF.", "danger")
        return redirect(url_for("scans.scan_detail", session_id=session_id))

# ---------------------
#  View Log File
# ---------------------
@bp.route("/logs/<int:session_id>")
def view_logs(session_id):
    """
    Render the full Nmap log file used for a scan session.
    Falls back to DB log_text if the .txt file no longer exists.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT log_path, log_text FROM scan_sessions WHERE id = ?", (session_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return "Log data not found", 404

    log_path, log_text = row

    if log_path and os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                log_content = f.read()
        except Exception as e:
            log_content = log_text or f"⚠️ Failed to read log file: {e}"
    elif log_text:
        log_content = log_text
    else:
        log_content = "⚠️ Log file not found and no log text available."

    return render_template("view_logs.html", log_content=log_content, session_id=session_id)

