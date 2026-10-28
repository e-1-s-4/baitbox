# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Runtime environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BAITBOX_DB=/data/baitbox.db \
    BAITBOX_SSH_HOST_KEY=/data/host_key \
    BAITBOX_DASHBOARD_PORT=8000

WORKDIR /app

# Install dependencies first so the layer is cached across source changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create the unprivileged runtime user *before* copying application files so
# that COPY --chown can resolve the owner.
RUN useradd --system --create-home --shell /usr/sbin/nologin honeypot \
    && mkdir -p /data && chown honeypot:honeypot /data

# Copy application code (owned by the unprivileged user)
COPY --chown=honeypot:honeypot . .

USER honeypot

# Expose SSH (2222), Telnet (2323), Dashboard + HTTP honeypot (8000)
EXPOSE 2222 2323 8000

# Persist database across container restarts
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"

CMD ["python", "-m", "baitbox.main"]
