# Reproducible Linux environment: optimized (Release) liboqs plus the full test suite.
FROM python:3.12-slim-bookworm AS base
ARG LIBOQS_VERSION=0.16.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake ninja-build git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
 && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /tmp/liboqs/build \
 && cmake --install /tmp/liboqs/build \
 && ldconfig \
 && rm -rf /tmp/liboqs
WORKDIR /app
COPY pyproject.toml README.md ./
COPY quantumkey ./quantumkey
RUN pip install --no-cache-dir -e ".[test,postgres]"
COPY . .
CMD ["python", "-m", "pytest", "-q"]
