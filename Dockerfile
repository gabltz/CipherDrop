# syntax=docker/dockerfile:1.7
# Base images are pinned by digest (Dependabot keeps them current).
# CipherDrop: multi-stage build producing a static binary on an empty (scratch) base.
#   docker build -t cipherdrop .
#   docker buildx build --platform linux/amd64,linux/arm64 -t cipherdrop .

# ---- 1. Frontend (Svelte + TypeScript SDK) ----------------------------------
FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS frontend
WORKDIR /src
COPY package.json package-lock.json .npmrc ./
COPY sdk/typescript/package.json sdk/typescript/
COPY frontend/package.json frontend/
COPY tests/e2e/package.json tests/e2e/
# --ignore-scripts: no dependency install scripts (blocks e.g. analytics postinstalls).
RUN npm ci --ignore-scripts --no-audit --no-fund -w cipherdrop-frontend -w @cipherdrop/sdk
COPY sdk/typescript sdk/typescript
COPY frontend frontend
COPY docs docs
RUN npm run build -w cipherdrop-frontend

# ---- 2. Rust (static musl binaries) -----------------------------------------
FROM rust:1.100-alpine@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS rust
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
COPY examples/rust examples/rust
COPY --from=frontend /src/frontend/dist /dist
ENV CIPHERDROP_DIST=/dist \
    CARGO_NET_RETRY=5
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p cipherdrop-server -p cipherdrop-cli \
 && install -D -m 0755 target/release/cipherdrop-server /out/cipherdrop-server \
 && install -D -m 0755 target/release/cipherdrop /out/cipherdrop \
 && /out/cipherdrop-server --version

# CA bundle for outbound TLS (only the CLI uses it; the server makes no outbound requests).
FROM alpine:3@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS certs
RUN apk add --no-cache ca-certificates

# ---- 3. Runtime --------------------------------------------------------------
FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=rust /out/cipherdrop-server /usr/local/bin/cipherdrop-server
COPY --from=rust /out/cipherdrop /usr/local/bin/cipherdrop
# Non-root, numeric UID/GID (no /etc/passwd needed).
USER 65532:65532
ENV CIPHERDROP__SERVER__LISTEN=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/cipherdrop-server", "healthcheck", "--addr", "127.0.0.1:8080"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/cipherdrop-server"]
CMD ["serve"]
