# parse2_nmap.py
# ------------------------
# Parses Nmap XML scan results and inserts them into the database,
# including risk scoring, tagging, and OS/service details.
# ------------------------

import inspect
import sys
import os
import sqlite3
import xml.etree.ElementTree as ET
from datetime import datetime

# Project-specific utility imports
from app.utils.db_utils import init_db, set_tag
from app.utils.risk_utils import compute_row_risk_score
from app.utils.tag_suggestions import suggest_tags
import logging

# ----------------------------------------
# Logger Setup
# ----------------------------------------

logger = logging.getLogger("parser_logger")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../logs"))
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "parser.log")
    file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

# ----------------------------------------
# DB path setup (fallback)
# ----------------------------------------

DB_PATH = "nmap_results.db"
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

# ----------------------------------------
# Helper functions for tag retrieval
# ----------------------------------------

def get_existing_tags(cursor, ip):
    """Fetch existing session-level tags for the given IP."""
    cursor.execute("SELECT tag_type, tag_value FROM tags WHERE ip = ?", (ip,))
    return {row[0]: row[1] for row in cursor.fetchall()}

def get_existing_global_tags(cursor, ip):
    """Fetch existing global tags for the given IP, if any."""
    cursor.execute("SELECT device_tag, service_tag FROM global_tags WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    return {
        "device": row[0] if row and row[0] else None,
        "service": row[1] if row and row[1] else None
    }

# ----------------------------------------
# OS and uptime extraction
# ----------------------------------------

def extract_os_info(host):
    """Extract OS match name and CPE from the host element."""
    os_elem = host.find("os")
    os_match = ""
    cpe = ""
    if os_elem is not None:
        osmatch_elem = os_elem.find("osmatch")
        if osmatch_elem is not None:
            os_match = osmatch_elem.attrib.get("name", "")
            cpe_elem = osmatch_elem.find("cpe")
            if cpe_elem is not None:
                cpe = cpe_elem.text
    return os_match, cpe

def extract_uptime_info(host):
    """Extract uptime (in seconds) and last boot time if available."""
    uptime = ""
    last_boot = ""
    uptime_elem = host.find("uptime")
    if uptime_elem is not None:
        uptime = uptime_elem.attrib.get("seconds", "")
        last_boot = uptime_elem.attrib.get("lastboot", "")
    return uptime, last_boot

# ----------------------------------------
# Script output parser (port level)
# ----------------------------------------

def parse_scripts(port):
    """Concatenate script output strings from <script> tags in a port."""
    outputs = [s.attrib.get("output", "") for s in port.findall("script")]
    return "; ".join(outputs)

# ----------------------------------------
# Database insert
# ----------------------------------------

def insert_scan_result(session_id, entry, cursor, risk_score=0):
    """Insert parsed host/port/service details into the scan_results table."""
    cursor.execute("""
        INSERT INTO scan_results (
            session_id, ip, hostname, mac_addr, vendor,
            protocol, port, state, service, product,
            version, os, cpe, uptime, last_boot, script, risk_score
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        session_id, entry["ip"], entry["hostname"], entry["mac_addr"], entry["vendor"],
        entry["protocol"], entry["port"], entry["state"], entry["service"], entry["product"],
        entry.get("version", ""), entry.get("os", ""), entry.get("cpe", ""),
        entry.get("uptime", ""), entry.get("last_boot", ""), entry.get("script", ""), risk_score
    ))

# ----------------------------------------
# Main parsing logic
# ----------------------------------------

def parse_and_insert(xml_path, log_path=None):
    """
    Main function to parse the XML file and insert data into the DB.

    Args:
        xml_path (str): Path to the Nmap XML scan file.
        log_path (str): Optional path to a corresponding log file.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    init_db()

    # Parse XML file
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error(f"❌ XML Parse Error: {e}")
        return
    except Exception as e:
        logger.error(f"❌ Unexpected Error: {e}")
        return

    # Extract scan metadata from filename
    filename = os.path.basename(xml_path)
    parts = filename.replace(".xml", "").split("_")
    scan_type = parts[1] if len(parts) >= 3 else "custom"
    timestamp = parts[-1].replace("T", " ") if len(parts) >= 3 else datetime.now().isoformat(timespec="seconds")

    # Read log text if provided
    log_text = ""
    if log_path and os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                log_text = f.read()
        except Exception as e:
            logger.warning(f"⚠️ Failed to read log file {log_path}: {e}")

    # Insert session metadata into DB
    logger.info(f"Inserting scan session: {timestamp}, type={scan_type}, file={xml_path}")
    try:
        cursor.execute("""
            INSERT INTO scan_sessions (timestamp, scan_type, xml_path, log_path, log_text)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, scan_type, xml_path, log_path, log_text))
        session_id = cursor.lastrowid
    except Exception as e:
        logger.error(f"❌ Failed to insert scan session: {e}")
        return

    if not session_id:
        logger.error("❌ session_id is None after insert")
        return

    total_device_tags = 0
    total_service_tags = 0

    # Loop through all <host> elements in the scan
    for host in root.findall("host"):
        if host.find("status") is not None and host.find("status").attrib.get("state") != "up":
            continue

        # IP and MAC address extraction
        addr = host.find("address[@addrtype='ipv4']")
        addr_ip = addr.attrib.get("addr") if addr is not None else "unknown"

        mac = host.find("address[@addrtype='mac']")
        mac_addr = mac.attrib.get("addr") if mac is not None else None
        vendor = mac.attrib.get("vendor") if mac is not None else None

        # Hostname extraction
        hostnames = host.find("hostnames")
        hostname = ""
        if hostnames is not None:
            name_elem = hostnames.find("hostname")
            if name_elem is not None:
                hostname = name_elem.attrib.get("name", "")

        # OS and uptime info
        os_match, cpe = extract_os_info(host)
        uptime, last_boot = extract_uptime_info(host)

        # Check for preexisting tags
        session_tags = get_existing_tags(cursor, addr_ip)
        global_tags = get_existing_global_tags(cursor, addr_ip)
        tagged = False

        ports_elem = host.find("ports")
        port_found = False

        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                # Basic port metadata
                state_elem = port.find("state")
                state = state_elem.attrib.get("state", "") if state_elem is not None else ""
                protocol = port.attrib.get("protocol", "")
                port_id = int(port.attrib.get("portid", "0"))

                # Service identification
                service_elem = port.find("service")
                service = service_elem.attrib.get("name", "") if service_elem is not None else ""
                product = service_elem.attrib.get("product", "") if service_elem is not None else ""
                version = service_elem.attrib.get("version", "") if service_elem is not None else ""

                # Script output (e.g. banners)
                script_output = parse_scripts(port)

                # Optional: Suggest tags if not already tagged
                if not tagged:
                    device_tag, service_tag = suggest_tags(addr_ip, port_id, service, mac_vendor=vendor, os_match=os_match)
                    if device_tag and not session_tags.get("device") and not global_tags.get("device"):
                        set_tag(session_id, addr_ip, mac_addr, "device", device_tag, cursor)
                        total_device_tags += 1
                    if service_tag and not session_tags.get("service") and not global_tags.get("service"):
                        set_tag(session_id, addr_ip, mac_addr, "service", service_tag, cursor)
                        total_service_tags += 1
                    tagged = True

                # Risk score computation
                risk = compute_row_risk_score(port_id, service)
                logger.debug(f"📊 RISK DEBUG: {addr_ip} {port_id}/{service} => {risk}")

                # Assemble entry and insert
                entry = {
                    "ip": addr_ip, "hostname": hostname, "mac_addr": mac_addr, "vendor": vendor,
                    "protocol": protocol, "port": port_id, "state": state, "service": service,
                    "product": product, "version": version, "os": os_match, "cpe": cpe,
                    "uptime": uptime, "last_boot": last_boot, "script": script_output
                }

                insert_scan_result(session_id, entry, cursor, risk_score=risk)
                port_found = True

        # Fallback entry if no ports were parsed
        if not port_found:
            entry = {
                "ip": addr_ip, "hostname": hostname, "mac_addr": mac_addr, "vendor": vendor,
                "protocol": "", "port": None, "state": "filtered",
                "service": "All ports filtered or closed", "product": "", "version": "",
                "os": os_match, "cpe": cpe, "uptime": uptime, "last_boot": last_boot, "script": ""
            }
            risk = compute_row_risk_score(None, "All ports filtered or closed")
            insert_scan_result(session_id, entry, cursor, risk_score=risk)

    conn.commit()
    conn.close()
    logger.info(f"✅ Parsed: {xml_path} | Device tags: {total_device_tags}, Service tags: {total_service_tags}")
    return session_id

# ----------------------------------------
# CLI interface for direct execution
# ----------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        logger.error("Usage: python3 parse2_nmap.py <scanfile.xml> [optional_logfile.txt]")
        sys.exit(1)

    xml_path = os.path.abspath(sys.argv[1])

    if len(sys.argv) > 2:
        log_path = sys.argv[2]
    else:
        # Infer log file path from XML file name
        xml_filename = os.path.basename(xml_path)
        log_filename = xml_filename.replace("scan_", "log_").replace(".xml", ".txt")
        log_path = os.path.join(os.path.dirname(xml_path), log_filename)

        if not os.path.exists(log_path):
            logger.warning(f"⚠️ Log file inferred as {log_path} but does not exist yet.")

    logger.info(f"Parsing XML: {xml_path} with log file: {log_path}")

    try:
        session_id = parse_and_insert(xml_path, log_path)
    except Exception as e:
        logger.error(f"❌ Unexpected error during parsing: {e}")
        print("ERROR:NO_SESSION_ID")
        sys.stdout.flush()
        sys.exit(1)

    if session_id:
        print(session_id)
    else:
        print("ERROR:NO_SESSION_ID")

