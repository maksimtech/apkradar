FROM python:3.12-slim-trixie

LABEL maintainer="maksimtech <github@maksimtech.com>"
LABEL org.opencontainers.image.title="APKRadar"
LABEL org.opencontainers.image.description="APK compliance auditor — GDPR art.9 — tracker detection, permissions analysis"
LABEL org.opencontainers.image.source="https://github.com/maksimtech/apkradar"
# `licenses`, plural: that is the key the standard names, and the singular
# is read by nothing.
LABEL org.opencontainers.image.licenses="MIT"

# Upgrade what the base image ships with, and install nothing: no code in this image
# runs a system binary. The APK is read by androguard, which is pure Python; the DPO
# letter goes out over SMTP from this package's own sender; `mailradar.checker` looks
# GPG keys up over HTTP, and `cookieradar.scanner` runs no Java. The `gpg` binary is
# run by `mailradar.sender`, which apkradar never imports.
#
# `gnupg` and `default-jre-headless` stood here from the first commit, used by nothing,
# and `gnupg` brought dirmngr → libldap2 → libsasl2-2 along — CVE-2026-107161 in
# cyrus-sasl2, with no fix in trixie, could only be closed by not installing it.
# tests/test_docker_contract.py keeps this list empty, tests/docker/inspect.sh checks
# the image agrees.
RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Where the package comes from:
#   local (default, CI) → the code in this repository
#   pypi                → apkradar==APKRADAR_VERSION from the index
#
# The default is local because a build with no arguments has to say something about the
# code in front of whoever ran it. With a PyPI default it said 2026.9.1 for ever, which
# is what stood here while this project was at 2026.43 — and nothing about it looked
# wrong.
ARG APKRADAR_SOURCE=local
ARG APKRADAR_VERSION=

COPY pyproject.toml README.md LICENSE /app/build/
COPY apkradar/ /app/build/apkradar/

# `--only-binary :all:` on both branches, so nothing is ever compiled while building
# this image. It is built for amd64 and arm64, and a dependency without an aarch64
# wheel would be compiled under QEMU — tens of minutes or an out-of-memory, in a
# release, the first time some dependency stops shipping one. The local branch has to
# build this package's own wheel first, since it is a source tree, and then installs
# that wheel under the same restriction.
RUN case "${APKRADAR_SOURCE}" in \
        local) pip wheel --no-deps --no-cache-dir --wheel-dir /app/wheel /app/build && \
               pip install --no-cache-dir --root-user-action=ignore --only-binary :all: /app/wheel/*.whl ;; \
        pypi) test -n "${APKRADAR_VERSION}" || { echo "APKRADAR_VERSION is required with APKRADAR_SOURCE=pypi" >&2; exit 1; } && \
              pip install --no-cache-dir --root-user-action=ignore --only-binary :all: "apkradar==${APKRADAR_VERSION}" ;; \
        *) echo "APKRADAR_SOURCE must be 'local' or 'pypi'" >&2; exit 1 ;; \
    esac && \
    rm -rf /app/build /app/wheel

RUN useradd -m -u 1000 apkradar && \
    mkdir -p /home/apkradar/.apkradar && \
    chown -R apkradar:apkradar /home/apkradar

USER apkradar
WORKDIR /home/apkradar

VOLUME ["/home/apkradar/.apkradar"]

ENTRYPOINT ["apkradar"]
CMD ["--help"]
