FROM python:3.11-slim

# libmagic is required by python-magic for captured-file type detection
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY ml ./ml
COPY cleanup_malware.py reclassify_unknowns.py ./

# Run as non-root; /app/data holds the SQLite DB and GeoIP database (volume)
RUN useradd --create-home --uid 1000 honeypot \
    && mkdir -p /app/data \
    && chown -R honeypot:honeypot /app
USER honeypot

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"

# --proxy-headers restores real client IPs (for rate limiting) behind the
# nginx container. Safe because the backend port is not published to the host.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
