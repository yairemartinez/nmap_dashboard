# risk_utils.py

"""
 Risk analysis utilities for Nmap scan results.

This module defines scoring weights for services and ports,
and computes a total risk score per host based on open ports and services.
"""

import sqlite3
from app.config import DB_PATH

# ----------------------------------------
#  Risk Weight Definitions
# ----------------------------------------

#  Risk scores for commonly targeted services
SERVICE_RISK_WEIGHTS = {
    "ssh": 2,
    "http": 1,
    "ftp": 3,
    "telnet": 5,
    "rdp": 4,
    "smb": 3,
    "smtp": 2,
    "dns": 1,
    "mysql": 3,
    "postgresql": 3,
    # Add more services as needed
}

#  Risk scores for commonly targeted ports
PORT_RISK_WEIGHTS = {
    21: 3,      # FTP
    22: 2,      # SSH
    23: 5,      # Telnet
    25: 2,      # SMTP
    53: 1,      # DNS
    80: 1,      # HTTP
    139: 3,     # NetBIOS
    1433: 4,    # MSSQL
    3306: 3,    # MySQL
    3389: 4,    # RDP
    445: 3      # SMB
}

#  Exportable combined dictionary for access
RISK_WEIGHTS = {
    'ports': PORT_RISK_WEIGHTS,
    'services': SERVICE_RISK_WEIGHTS
}

# ----------------------------------------
#  Risk Computation Logic
# ----------------------------------------

def compute_host_risk_and_reasons(cursor_or_session_id, session_id=None, ip=None):
    """
       Compute the risk score for a single host (if IP is provided) or all hosts in a session.

    Args:
        cursor_or_session_id (Union[cursor, int]):
            - If ip is provided: treat this as DB cursor, use session_id + ip
            - If ip is None: treat this as session_id

        session_id (int): Required if passing a cursor
        ip (str): Optional. Target specific host

    Returns:
        Tuple:
            - risk_by_host (dict): { ip: total_risk_score }
            - reasons_by_host (dict): { ip: [explanation strings] }
    """
    
    if ip is not None:
        #  Direct cursor usage mode
        cursor = cursor_or_session_id
        cursor.execute("""
            SELECT ip, port, service
            FROM scan_results
            WHERE session_id = ? AND ip = ? AND state = 'open'
        """, (session_id, ip))
        rows = cursor.fetchall()
    else:
        #  Legacy session-only mode
        session_id = cursor_or_session_id
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip, port, service
            FROM scan_results
            WHERE session_id = ? AND state = 'open'
        """, (session_id,))
        rows = cursor.fetchall()
        conn.close()

    risk_by_host = {}     #  IP → cumulative score
    reasons_by_host = {}  #  IP → list of reason strings

    for row_ip, port, service in rows:
        service = (service or "").lower()
        port_score = PORT_RISK_WEIGHTS.get(port, 0)
        service_score = SERVICE_RISK_WEIGHTS.get(service, 0)
        total_score = 1 + port_score + service_score  # ✅ Always include base score of 1

        risk_by_host[row_ip] = risk_by_host.get(row_ip, 0) + total_score
        reason = f"Port {port} (+{port_score}), Service '{service}' (+{service_score})"
        reasons_by_host.setdefault(row_ip, []).append(reason)

    return risk_by_host, reasons_by_host

# ----------------------------------------
#  Per-Row Risk Scoring
# ----------------------------------------

def compute_row_risk_score(port, service):
    """
       Compute a single row's risk score from port/service.

    Returns:
        int: Total score = 1 + port_score + service_score
    """
    try:
        port = int(port)
    except:
        port = 0  # 🛑 Default to 0 if not an integer

    service = (service or "").strip().lower()

    port_score = PORT_RISK_WEIGHTS.get(port, 0)
    service_score = SERVICE_RISK_WEIGHTS.get(service, 0)


    return 1 + port_score + service_score

