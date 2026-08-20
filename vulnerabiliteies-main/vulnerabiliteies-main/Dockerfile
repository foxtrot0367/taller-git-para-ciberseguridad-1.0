FROM python:3.12-slim

WORKDIR /app

# Herramientas de sistema necesarias para los retos (ping para CMDi, curl para healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        iputils-ping \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Dependencias Python
COPY setup/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Código de la aplicación
COPY vulnerable_app/ .

# Directorios y flags para los retos
RUN mkdir -p /app/data /tmp/uploads \
    && echo "FLAG{cmd_injection_rce}"       > /flag.txt \
    && echo "FLAG{upload_path_traversal}"   > /tmp/pwned_flag.txt

# Variables de entorno por defecto (sobreescribibles en docker-compose)
ENV DB_PATH=/app/data/users.db \
    UPLOAD_DIR=/tmp/uploads \
    FLASK_ENV=development \
    PYTHONUNBUFFERED=1

EXPOSE 5000

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:5000/api/health || exit 1

CMD ["python", "app.py"]
