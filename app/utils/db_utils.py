# app/utils/db_utils.py
# ---------------------
# Utility functions for working with the database
# ---------------------

import sqlite3
import os, sys
from flask import session, flash, redirect, url_for, has_request_context
from app.config import DB_PATH
from collections import defaultdict

# ---------------------
# 🔍 SCAN SESSION RETRIEVAL
# ---------------------

def get_scan_summaries(scan_type=None, timestamp=None):
    """
       Get a list of scan session summaries.
    Filters by optional scan_type and timestamp.
    Returns: List of tuples (id, timestamp, scan_type)
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    query = "SELECT id, timestamp, scan_type FROM scan_sessions WHERE 1=1"
    params = []
    if scan_type:
        query += " AND scan_type LIKE ?"
        params.append(f"%{scan_type}%")
    if timestamp:
        query += " AND timestamp LIKE ?"
        params.append(f"%{timestamp}%")
    query += " ORDER BY timestamp DESC"

    cursor.execute(query, params)
    results = cursor.fetchall()
    conn.close()
    return results

# 📋 SCAN RESULT DETAILS
# ---------------------

def get_scan_details(session_id, ip=None, port=None, service=None):
    """
    📄 Get detailed scan results for a session.
    Supports optional filtering by IP, port, or service name.
    Returns: List of result rows for the session.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    query = """
        SELECT ip, protocol, port, state, service, product, version, os, script,
              hostname, mac_addr, vendor, uptime, last_boot, cpe, risk_score
        FROM scan_results
        WHERE session_id = ?
    """

    params = [session_id]
    if ip:
        query += " AND ip LIKE ?"
        params.append(f"%{ip}%")
    if port:
        query += " AND port = ?"
        params.append(port)
    if service:
        query += " AND service LIKE ?"
        params.append(f"%{service}%")
    query += " ORDER BY ip, port"

    cursor.execute(query, params)
    results = cursor.fetchall()
    conn.close()
    return results

# ---------------------
# 📊 SCAN SUMMARY AGGREGATES
# ---------------------

def get_scan_summary(session_id):
    """
       Summarize scan results:
    - Total hosts scanned
    - Total ports seen
    - Open ports count
    - Unique service types
    - Top 10 ports and services by frequency
    Returns: Dictionary of summary statistics
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(DISTINCT ip) FROM scan_results WHERE session_id = ?", (session_id,))
    total_hosts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(port) FROM scan_results WHERE session_id = ?", (session_id,))
    total_ports = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_results WHERE session_id = ? AND state = 'open'", (session_id,))
    open_ports = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT service) FROM scan_results WHERE session_id = ?", (session_id,))
    unique_services = cursor.fetchone()[0]

    cursor.execute("""
        SELECT port, COUNT(*) FROM scan_results
        WHERE session_id = ?
        GROUP BY port ORDER BY COUNT(*) DESC LIMIT 10
    """, (session_id,))
    top_ports = cursor.fetchall()

    cursor.execute("""
        SELECT service, COUNT(*) FROM scan_results
        WHERE session_id = ?
        GROUP BY service ORDER BY COUNT(*) DESC LIMIT 10
    """, (session_id,))
    top_services = cursor.fetchall()

    conn.close()
    return {
        "total_hosts": total_hosts,
        "total_ports": total_ports,
        "open_ports": open_ports,
        "unique_services": unique_services,
        "top_ports": top_ports,
        "top_services": top_services
    }

# ---------------------
# 🕓 SESSION INFO RETRIEVAL
# ---------------------

def get_session_info(session_id):
    """
       Get timestamp and scan_type for a given session.
    Returns: Tuple (timestamp, scan_type), or ("N/A", "N/A") if not found.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, scan_type FROM scan_sessions WHERE id=?", (session_id,))
        result = cursor.fetchone()
        conn.close()
        return result if result else ("N/A", "N/A")
    except Exception as e:
        print(f"Error in get_session_info: {e}")
        return ("Error", "Error")


def get_hosts_and_ports(session_id):
    """
       Get hosts and ports for a scan session.
    Returns:
        - A set of distinct IPs (hosts) in the session
        - A dictionary mapping each IP to a set of its scanned ports
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT DISTINCT ip FROM scan_results WHERE session_id = ?", (session_id,))
    hosts = {row[0] for row in cur.fetchall()}

    cur.execute("SELECT ip, port FROM scan_results WHERE session_id = ?", (session_id,))
    port_map = {}
    for ip, port in cur.fetchall():
        port_map.setdefault(ip, set()).add(port)

    conn.close()
    return hosts, port_map


def delete_orphaned_results():
    """
    🧹 Delete scan_results that reference non-existent scan_sessions.
    Also runs VACUUM to compact the database.
    Returns:
        - Number of deleted rows, or -1 on error
    """
    results_deleted = 0
    try:
        with sqlite3.connect(DB_PATH, timeout=5.0) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scan_results WHERE session_id NOT IN (SELECT id FROM scan_sessions)")
            results_deleted = cursor.rowcount

            if has_request_context():
                session.pop("last_deleted", None)

        # Optimize DB file size after deletion
        with sqlite3.connect(DB_PATH) as vacuum_conn:
            vacuum_conn.isolation_level = None
            vacuum_conn.execute("VACUUM")

    except sqlite3.OperationalError as e:
        print(f"DB error in delete_orphaned_results: {e}")
        return -1

    return results_deleted

# ------------------------
# 🏷️ Tagging Functions
# ------------------------

def get_tags(ip, mac=None, session_id=None):
    """
       Retrieve global and suggested tags for a device based on IP/MAC/session.
    - Looks up from global_tags and session-specific tags table.
    - Fallbacks:
        - Uses MAC from scan_results if not provided.
        - Falls back to IP-only match if MAC/IP combo is missing.
    Returns: dict with 'global' and 'suggested' tags for 'device' and 'service'.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    row = None

    # Fallback: Look up MAC if not provided
    if not mac and session_id:
        cursor.execute("""
            SELECT mac_addr FROM scan_results
            WHERE session_id = ? AND ip = ? AND mac_addr IS NOT NULL AND mac_addr != ''
            ORDER BY id DESC LIMIT 1
        """, (session_id, ip))
        mac_row = cursor.fetchone()
        mac = mac_row[0] if mac_row else ""

    # Try to match IP and MAC combo
    if ip and mac:
        cursor.execute("""
            SELECT device_tag, service_tag FROM global_tags
            WHERE ip = ? AND mac_addr = ?
        """, (ip, mac))
        row = cursor.fetchone()

    # Fallback to IP-only lookup
    if not row:
        cursor.execute("""
            SELECT device_tag, service_tag FROM global_tags
            WHERE ip = ?
        """, (ip,))
        row = cursor.fetchone()

    global_device, global_service = row if row else ("", "")

    # Look up scan-specific suggested tags (from `tags` table)
    cursor.execute("""
        SELECT tag_value FROM tags WHERE ip = ? AND tag_type = 'device'
    """, (ip,))
    suggested_device = cursor.fetchone()
    suggested_device = suggested_device[0] if suggested_device else ""

    cursor.execute("""
        SELECT tag_value FROM tags WHERE ip = ? AND tag_type = 'service'
    """, (ip,))
    suggested_service = cursor.fetchone()
    suggested_service = suggested_service[0] if suggested_service else ""

    conn.close()

    return {
        "global": {
            "device": global_device,
            "service": global_service
        },
        "suggested": {
            "device": suggested_device,
            "service": suggested_service
        }
    }


def set_tag(session_id, ip, mac, tag_type, tag_value, cursor=None):
    """
       Insert or update tags for a device.
    - Handles both per-scan `tags` and persistent `global_tags`.
    - Normalizes MAC to empty string if None.
    - Can be used standalone or inside larger DB transaction.
    """
    should_close = False
    if cursor is None:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        should_close = True
    else:
        conn = None

    # Normalize missing MAC address
    mac = mac or ""

    # Insert/update per-scan tag
    cursor.execute("""
        INSERT INTO tags (session_id, ip, tag_type, tag_value)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(session_id, ip, tag_type)
        DO UPDATE SET tag_value = excluded.tag_value
    """, (session_id, ip, tag_type, tag_value))

    # Insert or update global tags based on type
    if tag_type == "device":
        cursor.execute("""
            INSERT INTO global_tags (ip, mac_addr, device_tag, service_tag)
            VALUES (?, ?, ?, COALESCE((
                SELECT service_tag FROM global_tags
                WHERE ip = ? AND mac_addr = ?
            ), ''))
            ON CONFLICT(ip, mac_addr)
            DO UPDATE SET device_tag = excluded.device_tag
        """, (ip, mac, tag_value, ip, mac))
    elif tag_type == "service":
        cursor.execute("""
            INSERT INTO global_tags (ip, mac_addr, device_tag, service_tag)
            VALUES (?, ?, COALESCE((
                SELECT device_tag FROM global_tags
                WHERE ip = ? AND mac_addr = ?
            ), ''), ?)
            ON CONFLICT(ip, mac_addr)
            DO UPDATE SET service_tag = excluded.service_tag
        """, (ip, mac, ip, mac, tag_value))

    if should_close:
        conn.commit()
        conn.close()


# ------------------------
# Diff Comparison Utilities
# ------------------------

# Main function to compute the differences between two scan sessions
def compute_diff(old_id, new_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # ------------------------
    # Helper functions to sanitize string values
    # ------------------------
    def clean(val):
        return (val or "").strip()

    def clean_lower(val):
        return clean(val).lower()

    # ------------------------
    # Collect unique IPs for both old and new sessions
    # ------------------------
    cur.execute("SELECT DISTINCT ip FROM scan_results WHERE session_id = ?", (new_id,))
    new_hosts = {row[0] for row in cur.fetchall() if row[0]}

    cur.execute("SELECT DISTINCT ip FROM scan_results WHERE session_id = ?", (old_id,))
    old_hosts = {row[0] for row in cur.fetchall() if row[0]}

    # ------------------------
    # Identify added and removed hosts
    # ------------------------
    added_hosts = new_hosts - old_hosts
    removed_hosts = old_hosts - new_hosts
    port_changes = {}

    # ------------------------
    # Check all IPs involved in either session
    # ------------------------
    all_ips = new_hosts.union(old_hosts)
    for ip in all_ips:
        # ------------------------
        # Fetch new scan data for this IP
        # ------------------------
        cur.execute("""SELECT port, state, service, version, product, os, cpe, uptime, last_boot, script
                       FROM scan_results WHERE session_id = ? AND ip = ?""", (new_id, ip))
        new_data = {}
        for row in cur.fetchall():
            port = row[0]
            if port is not None:
                new_data[int(port)] = {
                    "state": clean(row[1]),
                    "service": clean(row[2]),
                    "version": clean(row[3]),
                    "product": clean(row[4]),
                    "os": clean(row[5]),
                    "cpe": clean(row[6]),
                    "uptime": clean(row[7]),
                    "last_boot": clean(row[8]),
                    "script": clean(row[9])
                }

        # ------------------------
        # Fetch old scan data for this IP
        # ------------------------
        cur.execute("""SELECT port, state, service, version, product, os, cpe, uptime, last_boot, script
                       FROM scan_results WHERE session_id = ? AND ip = ?""", (old_id, ip))
        old_data = {}
        for row in cur.fetchall():
            port = row[0]
            if port is not None:
                old_data[int(port)] = {
                    "state": clean(row[1]),
                    "service": clean(row[2]),
                    "version": clean(row[3]),
                    "product": clean(row[4]),
                    "os": clean(row[5]),
                    "cpe": clean(row[6]),
                    "uptime": clean(row[7]),
                    "last_boot": clean(row[8]),
                    "script": clean(row[9])
                }

        # ------------------------
        # Build side-by-side diff for all changed ports
        # ------------------------
        ports = sorted(p for p in (set(new_data.keys()) | set(old_data.keys())) if p is not None)
        side_by_side = []

        for port in ports:
            old = old_data.get(port, {})
            new = new_data.get(port, {})

            changes = {"port": port}

            # Compare each relevant field
            if clean_lower(old.get("state", "")) != clean_lower(new.get("state", "")):
                changes["old_state"] = old.get("state", "—") or "—"
                changes["new_state"] = new.get("state", "—") or "—"

            if clean_lower(old.get("service", "")) != clean_lower(new.get("service", "")) or \
               clean_lower(old.get("version", "")) != clean_lower(new.get("version", "")):
                changes["old_svc_ver"] = f"{old.get('service', '')} {old.get('version', '')}".strip() or "—"
                changes["new_svc_ver"] = f"{new.get('service', '')} {new.get('version', '')}".strip() or "—"

            if clean_lower(old.get("product", "")) != clean_lower(new.get("product", "")):
                changes["old_product"] = old.get("product", "—") or "—"
                changes["new_product"] = new.get("product", "—") or "—"

            if clean_lower(old.get("os", "")) != clean_lower(new.get("os", "")):
                changes["old_os"] = old.get("os", "—") or "—"
                changes["new_os"] = new.get("os", "—") or "—"

            if clean_lower(old.get("cpe", "")) != clean_lower(new.get("cpe", "")):
                changes["old_cpe"] = old.get("cpe", "—") or "—"
                changes["new_cpe"] = new.get("cpe", "—") or "—"

            if (old.get("uptime") or "") != (new.get("uptime") or ""):
                changes["old_uptime"] = old.get("uptime", "—") or "—"
                changes["new_uptime"] = new.get("uptime", "—") or "—"

            if (old.get("last_boot") or "") != (new.get("last_boot") or ""):
                changes["old_last_boot"] = old.get("last_boot", "—") or "—"
                changes["new_last_boot"] = new.get("last_boot", "—") or "—"

            if clean_lower(old.get("script", "")) != clean_lower(new.get("script", "")):
                changes["old_script"] = old.get("script", "—") or "—"
                changes["new_script"] = new.get("script", "—") or "—"

            # Save full old/new values if any change detected
            if len(changes) > 1:
                changes["full_old"] = {
                    "state": old.get("state", "—") or "—",
                    "service": old.get("service", "—") or "—",
                    "version": old.get("version", "—") or "—",
                    "product": old.get("product", "—") or "—",
                    "os": old.get("os", "—") or "—",
                    "cpe": old.get("cpe", "—") or "—",
                    "uptime": old.get("uptime", "—") or "—",
                    "last_boot": old.get("last_boot", "—") or "—",
                    "script": old.get("script", "—") or "—"
                }
                changes["full_new"] = {
                    "state": new.get("state", "—") or "—",
                    "service": new.get("service", "—") or "—",
                    "version": new.get("version", "—") or "—",
                    "product": new.get("product", "—") or "—",
                    "os": new.get("os", "—") or "—",
                    "cpe": new.get("cpe", "—") or "—",
                    "uptime": new.get("uptime", "—") or "—",
                    "last_boot": new.get("last_boot", "—") or "—",
                    "script": new.get("script", "—") or "—"
                }
                side_by_side.append(changes)

        # ------------------------
        # Append hostname, MAC, and tags for this IP if any port changes
        # ------------------------
        if side_by_side:
            cur.execute("""SELECT hostname, mac_addr FROM scan_results
                           WHERE session_id = ? AND ip = ? LIMIT 1""", (new_id, ip))
            result = cur.fetchone()
            if not result:
                cur.execute("""SELECT hostname, mac_addr FROM scan_results
                               WHERE session_id = ? AND ip = ? LIMIT 1""", (old_id, ip))
                result = cur.fetchone()
            hostname, mac = result if result else ("", "")

            tags = []
            cur.execute("SELECT device_tag, service_tag FROM global_tags WHERE ip = ?", (ip,))
            tag_row = cur.fetchone()
            if tag_row:
                device_tag, service_tag = tag_row
                if device_tag:
                    tags.append(f"Device: {device_tag}")
                if service_tag:
                    tags.append(f"Service: {service_tag}")

            port_changes[ip] = {
                "side_by_side": side_by_side,
                "hostname": hostname,
                "mac": mac,
                "tags": tags
            }

    conn.close()

    # ------------------------
    # Return summary of changes
    # ------------------------
    return {
        "added_hosts": sorted(added_hosts),
        "removed_hosts": sorted(removed_hosts),
        "port_changes": port_changes
    }


# ------------------------
# Retrieve detailed info for a specific IP/Port combo from both sessions
# ------------------------
def get_detailed_port_info(old_id, new_id, ip, port):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    def get_info(session_id):
        cursor.execute("""
            SELECT * FROM scan_results
            WHERE session_id = ? AND ip = ? AND port = ?
        """, (session_id, ip, port))
        return cursor.fetchone()

    old_info = get_info(old_id)
    new_info = get_info(new_id)
    conn.close()

    return old_info, new_info

# ------------------------
# Initialization
# ------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            scan_type TEXT,
            xml_path TEXT,
            log_path TEXT,
            log_text TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            ip TEXT,
            hostname TEXT,
            mac_addr TEXT,
            vendor TEXT,
            protocol TEXT,
            port INTEGER,
            state TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            os TEXT,
            cpe TEXT,
            uptime TEXT,
            last_boot TEXT,
            script TEXT, risk_score INTEGER DEFAULT 0,
            FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            ip TEXT,
            tag_type TEXT,
            tag_value TEXT,
            UNIQUE(session_id, ip, tag_type),
            FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS global_tags (
            ip TEXT,
            mac_addr TEXT,
            device_tag TEXT,
            service_tag TEXT,
            PRIMARY KEY (ip, mac_addr)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_network (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT NOT NULL,
            ip TEXT,
            mac_addr TEXT NOT NULL UNIQUE,  -- Ensure no duplicate MACs
            status TEXT CHECK(status IN ('safe', 'temporary', 'unknown')) NOT NULL DEFAULT 'unknown'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            upload_time TEXT,
            session_id INTEGER,
            FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE SET NULL
        )
    """)

    conn.commit()
    conn.close()
    print("✅ Database initialized with all necessary tables.")

