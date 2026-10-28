FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 WORKER_DATA_DIR=/data
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1001 --create-home worker \
    && mkdir -p /data && chown worker:worker /data
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && ffmpeg -hide_banner -encoders 2>/dev/null | grep -q libx264 \
    && ffprobe -version >/dev/null
COPY --chown=worker:worker worker ./worker
USER worker
EXPOSE 8079
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8079/health', timeout=3)"
CMD ["uvicorn", "worker.app:app", "--host", "0.0.0.0", "--port", "8079", "--workers", "1", "--no-access-log", "--timeout-graceful-shutdown", "75"]
