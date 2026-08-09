# Dockerfile — multi-stage build for Sentry.
# Builds a static-ish binary in a rust image, then copies it into a
# distroless-style runtime image. Multi-arch via buildx (linux/amd64, linux/arm64).

# ── Stage 1: build ───────────────────────────────────────────────────────
FROM rust:1.97-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libpq-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first to cache deps.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY config ./config

# Build release. ONNX feature is opt-in; default build excludes it.
ARG FEATURES=default
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --features ${FEATURES} -p sentry-cli && \
    cp target/release/sentry /usr/local/bin/sentry

# ── Stage 2: runtime ─────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libpq5 tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root user.
RUN groupadd -r sentry && useradd -r -g sentry -d /var/lib/sentry -s /usr/sbin/nologin sentry
RUN mkdir -p /var/lib/sentry /etc/sentry && chown -R sentry:sentry /var/lib/sentry /etc/sentry

COPY --from=builder /usr/local/bin/sentry /usr/local/bin/sentry
COPY config/sentry.example.toml /etc/sentry/sentry.example.toml

USER sentry
WORKDIR /var/lib/sentry

ENV SENTRY_CONFIG=/etc/sentry/sentry.toml
EXPOSE 8080

ENTRYPOINT ["tini", "--", "sentry"]
CMD ["run"]