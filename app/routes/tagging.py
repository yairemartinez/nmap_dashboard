# app/routes/tagging.py

# ---------------------------------------
#  Flask Blueprint Setup for Tagging
# ---------------------------------------
from flask import Blueprint, render_template, request, redirect, flash, url_for
from app.config import DB_PATH
import sqlite3

bp = Blueprint("tagging", __name__)

# ---------------------------------------
#  View + Update Tag Inventory Page
# ---------------------------------------
@bp.route("/tag_inventory", methods=["GET", "POST"])
def tag_inventory():
    """
    View and update global tags (device/service) for (IP, MAC).
    
    - GET: Show all current tags in the global_tags table.
    - POST: Submit updated or new tags via form submission.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if request.method == "POST":
        total_rows = int(request.form.get("total_rows", 0))
        updates = []
        inserts = []

        for index in range(1, total_rows + 1):
            original_ip = request.form.get(f"original_ip_{index}", "").strip()
            original_mac = request.form.get(f"original_mac_{index}", "").strip()
            new_ip = request.form.get(f"ip_{index}", "").strip()
            new_mac = request.form.get(f"mac_{index}", "").strip()
            device_tag = request.form.get(f"device_tag_{index}", "").strip()
            service_tag = request.form.get(f"service_tag_{index}", "").strip()

            #  Skip rows where all fields are blank (no-op)
            if not new_ip and not new_mac and not device_tag and not service_tag:
                continue

            if original_ip and original_mac:
                #  Existing row: add to updates
                updates.append((new_ip, new_mac, device_tag, service_tag, original_ip, original_mac))
            elif new_ip:
                #  New entry: add to inserts (MAC optional)
                inserts.append((new_ip, new_mac or "", device_tag, service_tag))

        #  Apply updates to existing global_tags records
        if updates:
            cursor.executemany("""
                UPDATE global_tags
                SET ip = ?, mac_addr = ?, device_tag = ?, service_tag = ?
                WHERE ip = ? AND mac_addr = ?
            """, updates)

        # Insert new records if not duplicates
        if inserts:
            cursor.executemany("""
                INSERT OR IGNORE INTO global_tags (ip, mac_addr, device_tag, service_tag)
                VALUES (?, ?, ?, ?)
            """, inserts)

        conn.commit()
        flash("✅ Tags updated successfully!", "success")
        return redirect(url_for("tagging.tag_inventory"))

    # ---------------------------------------
    # Fetch and display all tagged hosts
    # ---------------------------------------
    cursor.execute("""
        SELECT 
            gt.ip, 
            COALESCE(gt.mac_addr, sr.mac_addr, '') AS mac_addr, 
            gt.device_tag, 
            gt.service_tag
        FROM global_tags gt
        LEFT JOIN scan_results sr 
            ON gt.ip = sr.ip
        GROUP BY gt.ip
        ORDER BY gt.ip
    """)
    tagged_hosts = cursor.fetchall()
    conn.close()

    return render_template("tag_inventory.html", tagged_hosts=tagged_hosts)

# ---------------------------------------
#  Delete Tag Entry
# ---------------------------------------
@bp.route("/delete_tag", methods=["POST"])
def delete_tag():
    """
    Deletes a global tag entry from global_tags.
    Supports:
      - IP + MAC (exact match)
      - IP only (all tags for IP)
      - MAC only (all tags with matching MAC, loose match)
    MAC addresses are normalized for loose comparison.
    """
    ip = request.form.get("ip", "").strip()
    mac = request.form.get("mac", "").strip().upper().replace(":", "").replace("-", "")
    deleted = 0
    deleted_target = ""

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if ip and mac:
        # Delete specific (IP + MAC), loose MAC match
        cursor.execute("""
            DELETE FROM global_tags 
            WHERE ip = ?
              AND REPLACE(REPLACE(UPPER(mac_addr), ':', ''), '-', '') = ?
        """, (ip, mac))
        deleted_target = f"{ip} / {mac}"

    elif ip:
        # Delete all tags for IP
        cursor.execute("""
            DELETE FROM global_tags 
            WHERE ip = ?
        """, (ip,))
        deleted_target = f"{ip} / all MACs"

    elif mac:
        # Delete all tags for matching MAC only
        cursor.execute("""
            DELETE FROM global_tags 
            WHERE REPLACE(REPLACE(UPPER(mac_addr), ':', ''), '-', '') = ?
        """, (mac,))
        deleted_target = f"[no IP] / {mac}"

    else:
        flash("❌ No IP or MAC provided for deletion", "danger")
        return redirect(url_for("tagging.tag_inventory"))

    deleted = cursor.rowcount
    conn.commit()
    conn.close()

    if deleted:
        flash(f"🗑 Deleted {deleted} tag(s) for {deleted_target}", "success")
    else:
        flash(f"⚠️ No matching tags found for {deleted_target}", "warning")

    return redirect(url_for("tagging.tag_inventory"))

