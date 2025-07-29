# app/utils/tagging_suggestions.py

# ----------------------------------------
# 🔍 suggest_tags()
# ----------------------------------------
# Heuristically assigns a (device_tag, service_tag) pair based on:
# - IP address patterns
# - Open port or known service
# - MAC vendor string
# - OS fingerprint match string
# ----------------------------------------

def suggest_tags(ip, port, service, mac_vendor=None, os_match=None):
    device_tag = ""
    service_tag = ""

    # ----------------------------------------
    # 🌐 IP-based Heuristics
    # ----------------------------------------
    if ip.endswith(".1"):
        device_tag = "Gateway"
    elif ip.endswith(".100"):
        device_tag = "Main Host"

    # ----------------------------------------
    # 📡 Port/Service-based Heuristics
    # ----------------------------------------
    if service in ["printer"] or port in [9100]:
        device_tag = device_tag or "Printer"
        service_tag = service_tag or "Printing"

    elif service in ["http", "https"] or port in [80, 443]:
        device_tag = device_tag or "Web Server"
        service_tag = service_tag or "Web Service"

    elif service == "ssh" or port == 22:
        device_tag = device_tag or "Linux Server"
        service_tag = service_tag or "Remote Access"

    elif service == "smb" or port == 445:
        service_tag = service_tag or "File Sharing"

    elif service in ["rdp", "ms-wbt-server"] or port == 3389:
        device_tag = device_tag or "Windows Server"
        service_tag = service_tag or "Remote Desktop"

    elif service in ["mysql", "postgresql"] or port in [3306, 5432]:
        service_tag = service_tag or "Database"

    elif service == "snmp" or port == 161:
        service_tag = service_tag or "Monitoring"

    # ----------------------------------------
    # 🏭 MAC Vendor-based Heuristics
    # ----------------------------------------
    if mac_vendor:
        vendor = mac_vendor.lower()
        if "hp" in vendor and "printer" in vendor:
            device_tag = device_tag or "Printer"
        elif "hp" in vendor:
            device_tag = device_tag or "HP Device"
        elif "cisco" in vendor:
            device_tag = device_tag or "Router"
        elif "ubiquiti" in vendor:
            device_tag = device_tag or "Access Point"
        elif "apple" in vendor:
            device_tag = device_tag or "Apple Device"
        elif "dell" in vendor:
            device_tag = device_tag or "Desktop"
        elif "raspberry" in vendor:
            device_tag = device_tag or "IoT Device"
        elif "mikrotik" in vendor:
            device_tag = device_tag or "Router"

    # ----------------------------------------
    # 🧠 OS Fingerprint Heuristics
    # ----------------------------------------
    if os_match:
        os_lower = os_match.lower()
        if "windows" in os_lower:
            device_tag = device_tag or "Windows Host"
        elif "linux" in os_lower or "ubuntu" in os_lower:
            device_tag = device_tag or "Linux Host"
        elif "routeros" in os_lower or "mikrotik" in os_lower:
            device_tag = device_tag or "Router"
        elif "nas" in os_lower:
            device_tag = device_tag or "NAS Device"
        elif "pfsense" in os_lower or "openbsd" in os_lower:
            device_tag = device_tag or "Firewall"
        elif "android" in os_lower:
            device_tag = device_tag or "Mobile Device"

    return device_tag, service_tag

