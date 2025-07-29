# app/routes/compare.py
# ---------------------
# Handles scan comparison routes
# ---------------------

from flask import Blueprint, request, render_template, flash, redirect, url_for
from app.utils.db_utils import get_scan_summaries, get_session_info, compute_diff
from app.utils.db_utils import get_detailed_port_info

#  Define a Flask Blueprint for scan comparison
bp = Blueprint("compare", __name__)

# -------------------------
#  Route: Comparison Form
# -------------------------
@bp.route("/compare", methods=["GET"])
def compare_form():
    """
    Renders the form to select two scan sessions for comparison.
    """
    #  Fetch summaries of all scan sessions
    scans = get_scan_summaries()

    #  Render selection form
    return render_template("compare_form.html", scans=scans)


# ----------------------------------------
# 🔍 Route: View Scan Comparison Results
# ----------------------------------------
@bp.route("/compare/view", methods=["GET"])
def compare_view():
    """
    Compares two scans by session ID and renders the difference view.
    """
    #  Get selected scan session IDs from query parameters
    old_id = request.args.get("old_id", type=int)
    new_id = request.args.get("new_id", type=int)

    #  Check both IDs are provided
    if not (old_id and new_id):
        flash("⚠️ Please select two scans to compare.", "warning")
        return redirect(url_for("compare.compare_form"))

    #  Prevent comparison of identical scans
    if old_id == new_id:
        flash("⚠️ Please select two different scans for comparison.", "warning")
        return redirect(url_for("compare.compare_form"))

    try:
        #  Compute the diff between scans
        diff = compute_diff(old_id, new_id)

        #  Get metadata for each scan session
        old_info = get_session_info(old_id)
        new_info = get_session_info(new_id)

        #  Render comparison template with all data
        return render_template(
            "compare.html",
            old_id=old_id,
            new_id=new_id,
            old_info=old_info,
            new_info=new_info,
            diff=diff,
        )

    except Exception as e:
        # ❌ Error during comparison process
        flash(f"❌ Error during comparison: {str(e)}", "danger")
        return redirect(url_for("compare.compare_form"))


# -------------------------------------------------
#  Route: Full Info Drill-Down on Specific Change
# -------------------------------------------------
@bp.route('/compare/full_info')
def full_info():
    """
    View detailed side-by-side port/service information for a given IP and port.
    Used in the comparison results view.
    """
    #  Extract parameters from URL query string
    old_id = request.args.get("old_id", type=int)
    new_id = request.args.get("new_id", type=int)
    ip = request.args.get("ip")
    port = request.args.get("port", type=int)

    #  Load detailed info (reuses logic from DB utility)
    old_info, new_info = get_detailed_port_info(old_id, new_id, ip, port)

    #  Render side-by-side comparison of the selected IP+port
    return render_template("full_info.html", ip=ip, port=port,
                           old_info=old_info, new_info=new_info,
                           old_id=old_id, new_id=new_id)

