# =============================================================
# AIPET Cloud — Dockerfile
# =============================================================
# What this file does:
#   Builds a Docker container with everything AIPET needs
#   to run in production. Starting from a clean Ubuntu image
#   it installs Python, system tools, and AIPET dependencies.
#
# Build:  docker build -t aipet-cloud .
# Run:    docker-compose up -d
# =============================================================

# Start from official Python 3.11 slim image
# Slim = smaller size, only essential components
FROM python:3.11-slim

# Who maintains this image
LABEL maintainer="Binyam <binyam@aipet.io>"
LABEL version="1.0.0"
LABEL description="AIPET Cloud — AI-Powered IoT Security"

# Set environment variables
# PYTHONDONTWRITEBYTECODE: dont create .pyc files
# PYTHONUNBUFFERED: print logs immediately (no buffering)
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production

# Set working directory inside container
WORKDIR /app

# Install system dependencies
# nmap: network scanning (Module 1)
# binwalk: firmware analysis (Module 5)
# mosquitto-clients: MQTT testing (Module 2)
RUN apt-get update && apt-get install -y \
    nmap \
    binwalk \
    mosquitto-clients \
    curl \
    gcc \
    libpq-dev \
    autoconf \
    automake \
    libtool \
    libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first
# Docker caches this layer — only reinstalls if
# requirements change (faster builds)
COPY requirements_docker.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements_docker.txt

# Copy the entire AIPET project
COPY . .

# Create directories for results and reports
RUN mkdir -p results reporting recon mqtt coap \
             http_attack firmware ai_engine/models \
             ai_engine/data

# Expose the API port
EXPOSE 5001

# Health check — Docker will restart container if this fails
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5001/api/health || exit 1

# Start Gunicorn when container starts
CMD ["gunicorn", \
     "--config", "dashboard/backend/gunicorn_config.py", \
     "dashboard.backend.app_cloud:app"]
