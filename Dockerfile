FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (unprivileged owner)
COPY --chown=honeypot:honeypot . .

# Run as a non-root user — the honeypot needs no privileged operations
RUN useradd --system --create-home --shell /usr/sbin/nologin honeypot \
    && mkdir -p /data && chown honeypot:honeypot /data
USER honeypot

# Expose SSH (2222), Telnet (2323), Dashboard + HTTP honeypot (8000)
EXPOSE 2222 2323 8000

# Persist database across container restarts
VOLUME ["/data"]
ENV BAITBOX_DB=/data/baitbox.db

# Generated SSH host keys live next to the database volume
ENV BAITBOX_SSH_HOST_KEY=/data/host_key

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"

CMD ["python", "-m", "baitbox.main"]
