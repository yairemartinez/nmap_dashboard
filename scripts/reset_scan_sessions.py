# reset_scan_sessions.py

import sqlite3
import os
import sys

# ----------------------------------------
# Resolve absolute path to database file
# ----------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
DB_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "nmap_results.db"))

# ----------------------------------------
# List of tables to clear (with sequence reset)
# ----------------------------------------
TABLES_TO_RESET = [
    "scan_sessions",
    "scan_results",
    "uploads",
    "tags",
    "global_tags",
    "user_network"
]

def reset_scan_sessions():
    print(f"📂 Using database at: {DB_PATH}")

    if not os.path.exists(DB_PATH):
        print("❌ ERROR: Database file not found.")
        sys.exit(1)

    print("⚠️  This will permanently delete all scan session data, tags, uploads, and known devices.")
    confirm = input("Are you absolutely sure? Type 'YES' to proceed: ").strip().upper()
    if confirm != "YES":
        print("❌ Operation aborted by user.")
        return

    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        for table in TABLES_TO_RESET:
            try:
                cur.execute(f"DELETE FROM {table}")
                cur.execute(f"DELETE FROM sqlite_sequence WHERE name='{table}'")
                print(f"✅ Cleared table: {table}")
            except sqlite3.OperationalError as e:
                print(f"⚠️  Skipped table '{table}': {e}")

        conn.commit()  # ✅ Must commit before VACUUM

        print("🧹 Running VACUUM to shrink database...")
        cur.execute("VACUUM")  # ✅ Now this will work
        print("✅ VACUUM complete. Database cleaned and compacted.")

        print("🎉 All data reset and file compacted.")

    except sqlite3.Error as e:
        print(f"❌ SQLite error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    reset_scan_sessions()


