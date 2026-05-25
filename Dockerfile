FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FAKESPOTTER_TRANSPORT=streamable_http
ENV FAKESPOTTER_PORT=8000
ENV FAKESPOTTER_TMP=/tmp/fakespotter

# System dependencies: ffmpeg for yt-dlp, libgl1 for OpenCV headless
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    libgl1 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN groupadd -r fakespotter && useradd -r -g fakespotter fakespotter

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=fakespotter:fakespotter src/ ./src/

# Create tmp dir with correct ownership
RUN mkdir -p /tmp/fakespotter && chown fakespotter:fakespotter /tmp/fakespotter

USER fakespotter

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx, sys; r=httpx.get('http://localhost:8000/health', timeout=5); sys.exit(0 if r.status_code < 400 else 1)" || exit 1

CMD ["python", "src/server.py"]
