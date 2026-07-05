FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose SSH (2222), Telnet (2323), Dashboard + HTTP honeypot (8000)
EXPOSE 2222 2323 8000

# Persist database across container restarts
VOLUME ["/data"]
ENV BAITBOX_DB=/data/baitbox.db

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"

CMD ["python", "-m", "baitbox.main"]
