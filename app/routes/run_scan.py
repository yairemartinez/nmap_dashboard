# app/routes/run_scan.py
# ---------------------
#  Scan execution and real-time progress streaming
# ---------------------

from flask import Blueprint, request, redirect, flash, url_for, jsonify, Response
from app.utils.scanner_presets import SCAN_CATEGORIES  
from app.utils.parse2_nmap import parse_and_insert     

import os
import time
import logging
import subprocess
import shutil
from threading import Thread
from datetime import datetime
import xml.etree.ElementTree as ET

bp = Blueprint("run_scan", __name__)  # 📍 Blueprint for routing scan-related endpoints


# ---------------------
#  Run Scan (Background Thread)
# ---------------------
@bp.route("/run_scan", methods=["POST"])
def run_scan():
    """
    Starts a background scan using selected category's Nmap arguments.
    Returns log filename for real-time progress tracking.
    """

    #  Fetch scan category and set scan target range
    category = request.form.get("category")
    target = "10.0.0.0/24"

    logging.info("Scan started for category: %s", category)

    #  Invalid category guard
    if category not in SCAN_CATEGORIES:
        flash("❌ Unknown scan category selected.", "danger")
        return redirect(url_for("core.index"))

    #  Generate unique output filenames based on timestamp
    timestamp = datetime.now().isoformat(timespec="microseconds").replace(":", "-").replace(".", "-")
    output_dir = "scans"
    os.makedirs(output_dir, exist_ok=True)

    #  Output XML and log paths (temporary & final)
    xml_filename = f"scan_{category.replace(' ', '_')}_{timestamp}.xml"
    tmp_xml_path = os.path.join(output_dir, xml_filename + ".tmp")
    final_xml_path = os.path.join(output_dir, xml_filename)

    log_filename = f"log_{category.replace(' ', '_')}_{timestamp}.txt"
    log_path = os.path.join(output_dir, log_filename)

    # ---------------------
    #  Background scan logic
    # ---------------------
    def background_scan():
        try:
            with open(log_path, "w") as log_file:
                #  Construct full Nmap command  no sudo for DOCKER sudo for Else
                #full_cmd = ["sudo", "nmap"] + SCAN_CATEGORIES[category]["nmap_args"] + [
                full_cmd = ["nmap"] + SCAN_CATEGORIES[category]["nmap_args"] + [
                    "-oX", tmp_xml_path, target
                ]
                logging.info("Running command: %s", " ".join(full_cmd))

                #  Start subprocess and write stdout to log
                process = subprocess.Popen(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in process.stdout:
                    log_file.write(line)
                    log_file.flush()
                process.wait()

            time.sleep(1)  # 🧹 Allow disk I/O to catch up

            # ✅ Validate XML before renaming
            try:
                ET.parse(tmp_xml_path)  # If XML is invalid, raise exception
            except ET.ParseError as e:
                corrupt_path = tmp_xml_path + ".corrupt"
                shutil.copy(tmp_xml_path, corrupt_path)
                with open(log_path, "a") as log_file:
                    log_file.write(f"[FATAL] XML parse error: {e}. Copied to {corrupt_path}\n")
                return

            #  Rename temp XML to final name
            os.rename(tmp_xml_path, final_xml_path)

            #  Parse results and insert into database
            parse_and_insert(final_xml_path, log_path)

        except Exception as e:
            #  Handle unexpected errors
            with open(log_path, "a") as log_file:
                log_file.write(f"[ERROR] {str(e)}\n")

    #  Run scan in background thread (non-blocking)
    Thread(target=background_scan).start()

    #  Return log filename to frontend for progress tracking
    return jsonify({"log": log_filename})


# ---------------------
#  Real-Time Scan Progress
# ---------------------
@bp.route("/scan_progress/<logfile>")
def scan_progress(logfile):
    """
    Streams real-time progress percent based on log file contents.
    Frontend consumes this via Server-Sent Events (SSE).
    """

    def stream():
        log_path = os.path.join("scans", logfile)
        last_pos = 0
        percent = 0

        #  Defined Nmap progress stages & their estimated percentages
        stages = [
            ("Initiating Ping Scan", 10),
            ("Completed Ping Scan", 20),
            ("Initiating SYN Stealth Scan", 30),
            ("Completed SYN Stealth Scan", 40),
            ("Initiating Service scan", 60),
            ("Completed Service scan", 80),
            ("OS detection", 90),
            ("Nmap done", 100),
        ]

        #  Monitor the log file for known stage markers
        while percent < 100:
            try:
                if os.path.exists(log_path):
                    with open(log_path, "r") as f:
                        f.seek(last_pos)
                        lines = f.read()
                        last_pos = f.tell()

                        for marker, stage_percent in stages:
                            if marker in lines and stage_percent > percent:
                                percent = stage_percent
                                yield f"data: {percent}\n\n"
                time.sleep(1)
            except GeneratorExit:
                break  #  Exit gracefully if client disconnects

    return Response(stream(), content_type="text/event-stream")

