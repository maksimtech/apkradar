FROM python:3.12-slim-trixie

LABEL maintainer="maksimtech <github@maksimtech.com>"
LABEL org.opencontainers.image.title="APKRadar"
LABEL org.opencontainers.image.description="APK compliance auditor — GDPR art.9 — tracker detection, permissions analysis"
LABEL org.opencontainers.image.source="https://github.com/maksimtech/apkradar"
LABEL org.opencontainers.image.license="MIT"

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        gnupg \
        default-jre-headless \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

ARG APKRADAR_VERSION=2026.9.1

RUN pip install --no-cache-dir --root-user-action=ignore \
    "apkradar==${APKRADAR_VERSION}"

RUN useradd -m -u 1000 apkradar && \
    mkdir -p /home/apkradar/.apkradar && \
    chown -R apkradar:apkradar /home/apkradar

USER apkradar
WORKDIR /home/apkradar

VOLUME ["/home/apkradar/.apkradar"]

ENTRYPOINT ["apkradar"]
CMD ["--help"]
