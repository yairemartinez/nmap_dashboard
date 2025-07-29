from flask import Flask
from .routes import tagging, scans, run_scan, core, compare, my_network
import app.config as config
from app.utils.db_utils import init_db
from app.utils import custom_logging
import os
from app.utils.db_utils import init_db

def create_app():
    app = Flask(__name__)

    init_db()

    # Configuration
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["DB_PATH"] = config.DB_PATH
    app.config["UPLOAD_FOLDER"] = config.UPLOAD_FOLDER

    # Register Blueprints
    app.register_blueprint(core.bp)
    app.register_blueprint(scans.bp)
    app.register_blueprint(compare.bp)
    app.register_blueprint(tagging.bp)
    app.register_blueprint(run_scan.bp)
    app.register_blueprint(my_network.bp)

    # ✅ Add security headers to every response
    @app.after_request
    def set_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response


    # Initialize database (once per app context)
    if not os.path.exists(config.DB_PATH):
        with app.app_context():
            print("🛠 Initializing DB for the first time...")
            init_db()
    else:
        print("✅ Using existing database.")

    return app

