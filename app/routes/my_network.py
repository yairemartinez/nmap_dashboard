# app/routes/my_network.py
# -------------------------
# Manages user-defined network devices (view, update, insert, delete)
# -------------------------

from flask import Blueprint, render_template, request, redirect, flash, url_for
from app.config import DB_PATH
import sqlite3
import logging
import ipaddress

#  Configure logger
logger = logging.getLogger("my_network")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.hasHandlers():
    handler = logging.FileHandler("logs/mynetwork.log")
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

#  Register blueprint
bp = Blueprint("my_network", __name__)


@bp.route("/my_network", methods=["GET", "POST"])
def my_network():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if request.method == "POST":
        total_rows = int(request.form.get("total_rows", 0))
        updates = []
        inserts = []

        for index in range(1, total_rows + 1):
            device_name = request.form.get(f"device_name_{index}", "").strip()
            ip = request.form.get(f"ip_{index}", "").strip()
            mac = request.form.get(f"mac_{index}", "").strip()
            status = request.form.get(f"status_{index}", "").strip()
            original_mac = request.form.get(f"original_mac_{index}", "").strip()

            mac = mac.upper().replace(":", "").replace("-", "").strip()
            original_mac = original_mac.upper().replace(":", "").replace("-", "").strip()

            # IP format check
            if ip and not is_valid_ip(ip):
                logger.warning(f"Skipping invalid IP in row {index}")
                continue

            # Status validation
            if status and status not in {"safe", "temporary", "unknown", ""}:
                logger.warning(f"Skipping invalid status in row {index}")
                continue

            if original_mac:
                updates.append((device_name, ip, mac, status, original_mac))
            elif mac:
                inserts.append((device_name, ip, mac, status))

        if updates:
            logger.info(f"Updating {len(updates)} device(s)")
            cursor.executemany("""
                UPDATE user_network
                SET device_name = ?, ip = ?, mac_addr = ?, status = ?
                WHERE mac_addr = ?
            """, updates)

        if inserts:
            logger.info(f"Inserting {len(inserts)} new device(s)")
            cursor.executemany("""
                INSERT OR IGNORE INTO user_network (device_name, ip, mac_addr, status)
                VALUES (?, ?, ?, ?)
            """, inserts)

        conn.commit()
        conn.close()

        logger.info("Network devices saved to database")
        flash("✅ Network devices updated!", "success")
        return redirect(url_for("my_network.my_network"))

    cursor.execute("SELECT device_name, ip, mac_addr, status FROM user_network ORDER BY ip")
    devices = cursor.fetchall()
    conn.close()

    return render_template("my_network.html", devices=devices)


@bp.route("/my_network/delete", methods=["POST"])
def delete_device():
    mac_addr = request.form.get("mac_addr", "").strip()
    ip = request.form.get("ip", "").strip()
    device_name = request.form.get("device_name", "").strip()
    row_index = request.form.get("row_index", "").strip()

    mac_addr = mac_addr.upper().replace(":", "").replace("-", "")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if mac_addr:
        logger.info("Attempting to delete device by MAC")
        cursor.execute("""
            DELETE FROM user_network
            WHERE REPLACE(REPLACE(mac_addr, ':', ''), '-', '') = ?
        """, (mac_addr,))
    elif ip and device_name:
        logger.info("Deleting device by IP and name")
        cursor.execute("""
            DELETE FROM user_network
            WHERE ip = ? AND device_name = ?
        """, (ip, device_name))
    else:
        logger.error("Delete failed: no valid identifier provided")
        conn.close()
        return "No valid identifier", 400

    conn.commit()
    deleted_count = cursor.rowcount
    conn.close()

    if deleted_count == 0:
        logger.warning("No devices deleted")
        return "Not found", 404

    logger.info("Device deleted")
    return "Deleted", 200


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

