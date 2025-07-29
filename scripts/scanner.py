import subprocess
import os
import sys
from datetime import datetime
from app.utils.db_utils import get_db_connection, ensure_db_schema
import argparse

def run_scan(scan_type, target_subnet):
    output_folder = "scans"
    os.makedirs(output_folder, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_file = os.path.join(output_folder, f"scan_{scan_type}_{timestamp}.xml")

    if scan_type == "light":
        nmap_cmd = [
            "sudo", "nmap", "-O", "-sS", "-Pn", "--version-light", "-T4",
            "-oX", output_file, target_subnet
        ]
    elif scan_type == "deep":
        nmap_cmd = [
            "sudo", "nmap", "-sS", "-sU", "-O", "-sV", "--version-light", "--script=default",
            "-p", "22,23,25,53,67,68,69,80,110,123,135,137,138,139,143,161,443,445,993,995,1900,3306,3389,5000,5353,5432,8080,8888",
            "-T4", "-oX", output_file, target_subnet
        ]
    else:
        print(f"❌ Unknown scan type: {scan_type}")
        sys.exit(1)

    try:
        print(f"🔍 Running {scan_type} scan on {target_subnet}...")
        subprocess.run(nmap_cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Nmap scan failed: {e}")
        sys.exit(1)

    # Ensure DB schema is ready
    ensure_db_schema()
    conn = get_db_connection()
    conn.close()

    # Parse XML and insert into DB
    try:
        print("🧠 Parsing XML into database...")
        subprocess.run(
            ["python3", "app/routes/parse2_nmap.py", output_file, scan_type],
            check=True
        )
        print("✅ Scan complete and parsed.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Parsing failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Nmap scans and parse results into the dashboard")
    parser.add_argument("--type", choices=["light", "deep"], default="deep", help="Type of scan to run")
    parser.add_argument("--subnet", default="10.0.0.0/24", help="Target subnet to scan")
    args = parser.parse_args()

    run_scan(args.type, args.subnet)

