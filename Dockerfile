FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get -o Acquire::Retries=5 \
            -o Acquire::http::Timeout=30 \
            -o Acquire::https::Timeout=30 \
            update; \
    apt-get -o Acquire::Retries=5 \
            -o Acquire::http::Timeout=30 \
            -o Acquire::https::Timeout=30 \
            install -y --no-install-recommends \
            ca-certificates \
            iputils-ping \
            iproute2 \
            net-tools \
            snmp \
            openssl \
            gcc \
            libpq-dev; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY . /app

RUN useradd --system --uid 10001 --create-home inventory \
    && mkdir -p /app/data /app/logs \
    && chown -R inventory:inventory /app/data /app/logs

USER inventory
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--timeout", "120", "app:app"]
