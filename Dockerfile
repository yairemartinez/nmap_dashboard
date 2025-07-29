# ------------------------------------------
# Base Image
# ------------------------------------------
FROM python:3.11-slim

# This is informational only. It tells others who maintains the project.
LABEL maintainer="yairemartinez"


# ------------------------------------------
# Environment Configuration
# ------------------------------------------
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ------------------------------------------
# Create Working Directory
# ------------------------------------------
WORKDIR /app

# ------------------------------------------
# Install system dependencies and build tools
# ------------------------------------------
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libssh2-1-dev \
    libpcap-dev \
    libpcre2-dev \
    liblua5.4-dev \
    zlib1g-dev \
    wget \
    curl \
    git \
    pkg-config \
    libxml2 \
    libxslt1.1 \
    libmagic1 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# ------------------------------------------
# Install latest Nmap from source (7.94SVN)
# ------------------------------------------
RUN git clone https://github.com/nmap/nmap.git /opt/nmap && \
    cd /opt/nmap && \
    ./configure && \
    make -j$(nproc) && \
    make install

# ------------------------------------------
# Copy Application Files
# ------------------------------------------
COPY app/ app/
COPY scans/ scans/
COPY scripts/ scripts/
COPY requirements.txt .
COPY wsgi.py .

# ------------------------------------------
# Install Python Dependencies
# ------------------------------------------
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ------------------------------------------
# Create Logs Directory
# ------------------------------------------
RUN mkdir -p /app/logs

# ------------------------------------------
# Expose Port (5050)
# ------------------------------------------
EXPOSE 5050

# ------------------------------------------
# Run the Application with Gunicorn
# ------------------------------------------
CMD ["gunicorn", "wsgi:app", "--bind", "0.0.0.0:5050", "--workers", "3", "--worker-class", "gevent", "--timeout", "300", "--access-logfile", "/app/logs/nmap_dashboard.log", "--access-logformat", "%(h)s %(l)s %(u)s [%(t)s] \\\"%(m)s %(U)s %(H)s\\\" %(s)s %(b)s", "--error-logfile", "-"]
#!/bin/bash

