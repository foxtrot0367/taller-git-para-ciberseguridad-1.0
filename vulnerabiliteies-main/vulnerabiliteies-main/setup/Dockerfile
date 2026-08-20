FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY setup/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vulnerable_app/ .

# Flag para el reto de RCE
RUN echo "FLAG{cmd_injection_rce}" > /flag.txt

EXPOSE 5000
CMD ["python", "app.py"]
