# syntax=docker/dockerfile:1
# Reproducible Linux environment: optimized (Release) liboqs plus the full test suite.
#
# Behind a TLS-inspecting proxy or antivirus, pass its root certificate as a build secret:
#   docker build --secret id=extra_ca,src=<root-ca.pem> -t quantumkey:dev .
# The certificate is trusted only by the download steps below and is not stored in the image.
FROM python:3.12-slim-bookworm AS base
ARG LIBOQS_VERSION=0.16.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake ninja-build git ca-certificates libssl-dev \
 && rm -rf /var/lib/apt/lists/*
# Prints the CA bundle for HTTPS downloads: the system bundle, plus the extra_ca secret if given.
RUN printf '%s\n' '#!/bin/sh' \
      'cat /etc/ssl/certs/ca-certificates.crt' \
      '[ -s /run/secrets/extra_ca ] && cat /run/secrets/extra_ca' \
      'exit 0' > /usr/local/bin/qk-ca-bundle \
 && chmod +x /usr/local/bin/qk-ca-bundle
RUN --mount=type=secret,id=extra_ca,required=false \
    qk-ca-bundle > /tmp/ca.pem \
 && GIT_SSL_CAINFO=/tmp/ca.pem git clone --depth 1 --branch ${LIBOQS_VERSION} \
      https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
 && rm /tmp/ca.pem \
 && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /tmp/liboqs/build \
 && cmake --install /tmp/liboqs/build \
 && ldconfig \
 && rm -rf /tmp/liboqs
WORKDIR /app
COPY pyproject.toml README.md ./
COPY quantumkey ./quantumkey
RUN --mount=type=secret,id=extra_ca,required=false \
    qk-ca-bundle > /tmp/ca.pem \
 && PIP_CERT=/tmp/ca.pem pip install --no-cache-dir -e ".[test,postgres]" \
 && rm /tmp/ca.pem
COPY . .
CMD ["python", "-m", "pytest", "-q"]
