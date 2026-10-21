FROM python:3.11-slim

LABEL maintainer="ARAGOS Core"
LABEL description="ARAGOS v3.0 — Neural Cyber Reconnaissance & OSINT Web Platform"
LABEL version="3.0.0"

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive
ENV PORT=8000

RUN groupadd -r aragos && useradd -r -g aragos aragos

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    curl \
    whois \
    dnsutils \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/results /app/logs /app/config && \
    chown -R aragos:aragos /app && \
    chmod +x /app/start-aragos.sh

USER aragos

VOLUME ["/app/results", "/app/config"]

EXPOSE 8000

CMD ["python3", "server.py"]
