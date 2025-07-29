# wsgi.py
"""
WSGI entry point for running the Nmap Dashboard in production.
Use with Gunicorn or any WSGI-compatible server.
"""
import app.utils.custom_logging
from app import create_app
# Create the Flask app instance using the factory function
app = create_app()

# Optional: Log when app is initialized (useful in logs/debug)
if __name__ == "__main__":
    print("⚙️  WSGI: App instance created. Use with Gunicorn.")
