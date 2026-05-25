FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FAKESPOTTER_TRANSPORT=streamable_http
ENV FAKESPOTTER_PORT=8000
ENV FAKESPOTTER_TMP=/tmp/fakespotter

# libgl1 + libglib2.0-0 required by opencv-python-headless
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r fakespotter && useradd -r -g fakespotter fakespotter

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=fakespotter:fakespotter src/ ./src/

RUN mkdir -p /tmp/fakespotter && chown fakespotter:fakespotter /tmp/fakespotter

USER fakespotter

EXPOSE 8000

CMD ["python", "src/server.py"]
