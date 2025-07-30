## 📽️ Live Demo

![Nmap Dashboard Demo](https://raw.githubusercontent.com/yairemartinez/nmap_dashboard/refs/heads/main/dashboard.gif)

⚠️ This tool is intended for private/local use only. Do not expose the app or container to the public internet.
⚠️ This app requires Docker to be run with sudo:

This is necessary because:
- Nmap needs raw socket access, which requires elevated privileges.
- Log files (`logs/nmap_dashboard.log`) are owned by root for security.
- The app runs in Docker containers as root by design.

Do not attempt to run without `sudo` unless you've reconfigured file permissions and container user behavior. 
If running app on docker edit app/routes/run_scan.py line 63 remove "sudo"(already done when posted)
TARGET IS HARDCODED line 34 app/routes/run_scan.py


# Nmap Dashboard
A self-contained, Flask-powered Nmap scanning dashboard for managing, visualizing, tagging, and comparing network scan results.
Built for personal network reconnaissance. Dockerized for portability. No external dependencies required beyond Docker.

# Features
- View and manage Nmap scan results through a web UI
- Tag devices and ports with custom labels
- Compare scans over time and track changes
- Export results to PDF
- Undo deletions and recover orphaned data
- Stream scan output live
- Built-in support for custom device tracking
- Fully containerized with Docker

nmap_dashboard/
├── app/ # All Flask route modules, templates, and utilities
├── archive/ # Archived scan data or backups
├── scans/ # XML (.xml) and plain text (.txt) scan outputs
├── logs/ # App logs written by logging module
├── scripts/ # Standalone backend scripts (not part of the dashboard UI)
├── nmap_results.db # SQLite database storing scan + tag data
├── Dockerfile # Docker image definition (installs Nmap + Flask app)
├── docker-compose.yml # Orchestrates container with volume/network config
├── requirements.txt # Python dependencies
├── .dockerignore # Files to ignore when building Docker image
├── .gitignore # Files to ignore from Git tracking
├── .env # Secret config variables (SECRET_KEY, etc.)
├── gunicorn.conf.py # Gunicorn server configuration for production
├── wsgi.py # Gunicorn entrypoint for Flask app
└── run.py # Dev-only script to launch app manually with Flask


# Development Tips
If you're not using Docker (for development only):
# Activate your venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# Run Flask dev server
python run.py


# Getting Started (with Docker)
# Requirements
- Docker v20+
- Linux-based OS (needed for `--network host` support)
- Open port 5050 (or change it in the Dockerfile)


# Docker Compose Explained
Here’s what Docker does under the hood:
Builds the image from Dockerfile
Installs latest Nmap from source
Runs the Flask app via Gunicorn
Maps scans/, logs/, and your SQLite DB as volumes
Uses network_mode: host for raw socket support (Nmap)
Loads secrets from .env

# Secrets are read from .env: YOU HAVE TO CREATE ONE
SECRET_KEY=replace-this-key
PYTHONDONTWRITEBYTECODE=1
PYTHONUNBUFFERED=1

DOWNLOARDING DOCKER
sudo apt update
sudo apt install docker.io -y
sudo apt install docker-compose -y

My Setup for Compose 
1.  mkdir -p /usr/local/lib/docker/cli-plugins/

2.  sudo curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
  -o /usr/local/lib/docker/cli-plugins/docker-compose 

3.  sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

USEFUL COMANDS FOR DOCKER
CHECK DOCKER STATUS sudo docker ps
CHECK DOCKER LOGS sudo docker compose logs -f


DOCKER WITHOUT COMPOSE
1. sudo docker build -t nmap-dashboard .

2. sudo docker stop nmap-app

3. sudo docker rm nmap-app

4. sudo docker run -d \
  --name nmap-app \
  --network host \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v $(pwd)/scans:/app/scans \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/nmap_results.db:/app/nmap_results.db \
  -v /etc/hosts:/etc/hosts:ro \
  -v /etc/resolv.conf:/etc/resolv.conf:ro \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -e PYTHONUNBUFFERED=1 \
  -e SECRET_KEY=replace-this-key \
  nmap-dashboard


DOCKERFILE WITH DOCKER COMPOSE
if running app on docker edit app/routes/run_scan.py line 63 remove "sudo"
1.Build the Container Image
sudo docker compose build
or
sudo docker compose up --build
2.Start the Container
sudo docker compose up -d

3.STOP THE APP
sudo docker compose down



## ⚠️ Security Notice

This tool is for **private use on trusted networks** only.  
Do **not** expose the container to the public internet or run on unknown devices.

The app uses:
- `network_mode: host` for low-level socket access (needed by Nmap)
- `--cap-add=NET_RAW` and `NET_ADMIN` which are powerful privileges

Run only on systems you control.

