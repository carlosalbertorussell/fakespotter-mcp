# Usa una versión específica para asegurar la reproducibilidad
FROM python:3.14-slim-bookworm 

# Evitar logs de caché y buffers
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FAKESPOTTER_TRANSPORT=streamable_http
ENV FAKESPOTTER_PORT=8000
ENV FAKESPOTTER_TMP=/tmp/fakespotter

# Instalar solo lo estrictamente necesario
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Crear usuario con UID definido (seguridad estándar en k8s/entornos cloud)
RUN groupadd -r fakespotter && useradd -r -g fakespotter -u 10001 fakespotter

WORKDIR /app

# Instalar dependencias con hashes (opcional pero recomendado)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY --chown=fakespotter:fakespotter src/ ./src/

# Crear y asegurar el directorio temporal
RUN mkdir -p /tmp/fakespotter && chown -R fakespotter:fakespotter /tmp/fakespotter

# Configurar permisos de solo lectura para el directorio /app 
# (Hardening: el usuario fakespotter no debe poder editar el código de la app)
RUN chmod -R 555 /app/src

USER fakespotter

EXPOSE 8000

CMD ["python", "src/server.py"]
