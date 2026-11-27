# Deployment

CipherDrop is a single executable (`cipherdrop-server`) with the web interface embedded. It needs no database, cache or other service. In the default ephemeral mode it needs no writable storage at all.

## Requirements

- Linux (amd64 or arm64) for production; macOS and other Unixes work for development.
- HTTPS, either native (`[server.tls]`) or through a reverse proxy. Browsers expose the Web Crypto API only in secure contexts.
- Memory: set `storage.max_memory_mb` below the container memory limit, leaving headroom for in-flight requests (roughly `max_concurrent_requests × 3 × max_size_bytes` in the worst case) and about 20 MiB of process overhead.

## Production pipeline

`deploy/production/` in the repository contains a complete production setup for a Linux host in one of three modes: behind a reverse proxy on the same host, behind a reverse proxy on another server (with the backend port restricted to the proxy's address), or standalone with a bundled Caddy that provides automatic HTTPS. It includes:

- a single `install.sh` that sets up the host and asks for the mode and port
- a hardened Compose stack
- ready-made nginx, Caddy, Apache and Traefik configurations
- `cipherdropctl` and a systemd timer: the host itself pulls each release built by `.github/workflows/release.yml`, verifies its Sigstore signature, deploys it with health and smoke checks, and rolls back automatically

Its `README.md` is the operator runbook.

## Docker

The image is built from `Dockerfile` (multi-stage: Node builds the frontend, Rust builds a static musl binary, and the runtime image is `scratch`-based with only the binary and CA certificates). It runs as UID 65532, exposes port 8080, and has a `HEALTHCHECK` using the binary itself.

Release images are published as `ghcr.io/gabltz/cipherdrop:vX.Y.Z` (and `:latest` for the newest stable release), for amd64 and arm64, with an SBOM, provenance and a Sigstore signature. To build your own:

```bash
docker build -t cipherdrop:latest .
docker buildx build --platform linux/amd64,linux/arm64 -t registry.example.com/cipherdrop:0.1.0 --push .
```

### Docker Compose

`compose.yml` in the repository runs CipherDrop with a read-only root filesystem, every capability dropped, `no-new-privileges`, memory, CPU and PID limits, core dumps disabled, and no volumes:

```yaml
services:
  cipherdrop:
    image: ghcr.io/gabltz/cipherdrop:latest
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 256m
    memswap_limit: 256m        # equal to mem_limit: the container may not use swap
    cpus: 1.0
    pids_limit: 128
    ulimits:
      core: 0
    environment:
      CIPHERDROP__SERVER__LISTEN: "0.0.0.0:8080"
      CIPHERDROP__SERVER__PUBLIC_URL: "https://paste.example.com"
      CIPHERDROP__SECURITY__TRUST_FORWARDED_HEADERS: "true"
      CIPHERDROP__SECURITY__TRUSTED_PROXIES: '["172.16.0.0/12"]'
      CIPHERDROP__STORAGE__MAX_MEMORY_MB: "128"
```

For persistent shares, mount a volume for `storage.sqlite_path` only, owned by UID 65532 with mode `0700`.

## Native systemd service

`deploy/systemd/cipherdrop.service` runs the binary as a dynamic user with a strict sandbox (`ProtectSystem=strict`, `MemoryDenyWriteExecute`, `LimitCORE=0`, `MemorySwapMax=0`, an empty capability set, and system-call filtering):

```bash
install -m 0755 target/release/cipherdrop-server /usr/local/bin/
install -m 0640 -D config.example.toml /etc/cipherdrop/config.toml
install -m 0644 deploy/systemd/cipherdrop.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now cipherdrop
```

## Reverse proxies

Configure CipherDrop to trust the proxy:

```toml
[server]
listen = "127.0.0.1:8080"          # or the container/network address
public_url = "https://paste.example.com"

[security]
trust_forwarded_headers = true
trusted_proxies = ["127.0.0.1/32"]
```

Every proxy MUST:

1. Terminate TLS and set `X-Forwarded-Proto` and `X-Forwarded-For` (overwriting client-supplied values).
2. **Not buffer request bodies to disk**, and not log request bodies or full URLs with sensitive paths.
3. Limit body size to roughly 1.4× `shares.max_size_bytes`.
4. Not cache `/api/` responses (CipherDrop sends `no-store`).

Ready-to-use configurations live in `deploy/`: `deploy/nginx/cipherdrop.conf`, `deploy/caddy/Caddyfile` and `deploy/traefik/` (dynamic configuration and Compose labels).

**Nginx** (excerpt):

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $remote_addr;   # overwrite, do not append untrusted values
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_request_buffering off;        # stream bodies: no client_body temp files
    proxy_buffering off;                # do not spool responses (ciphertext) to disk
    client_max_body_size 2m;
    access_log /var/log/nginx/cipherdrop.log privacy;  # log format without $request_uri
}
```

**Caddy**:

```caddyfile
paste.example.com {
    request_body { max_size 2MB }
    reverse_proxy 127.0.0.1:8080 {
        flush_interval -1
    }
    log { output discard }
}
```

## Keeping secrets out of persistent storage

CipherDrop never writes ephemeral shares to disk, but the operating system and infrastructure can:

| Risk | Mitigation |
|---|---|
| **Swap** | Disable swap on the host, or use `memswap_limit = mem_limit` (Docker), `MemorySwapMax=0` (systemd), or `security.lock_memory = true` (needs `CAP_IPC_LOCK`; locks all process memory) |
| **Hibernation** | Disable hibernation and suspend-to-disk on hosts running CipherDrop |
| **Core dumps** | Disabled by CipherDrop itself (`RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`). Also set `ulimits: core: 0` / `LimitCORE=0` and disable `systemd-coredump` / `apport` collection |
| **Hypervisor snapshots and live migration** | VM snapshots capture RAM. Exclude CipherDrop VMs from memory snapshots, or accept that snapshot storage holds ciphertext (never keys) |
| **Container checkpoints** (CRIU, `docker checkpoint`) | Do not checkpoint CipherDrop containers |
| **Reverse proxy buffering** | `proxy_request_buffering off; proxy_buffering off;` (nginx). Caddy and Traefik stream by default; avoid buffering middlewares |
| **Request body temp files** | Same as above; also make sure WAFs and API gateways in front do not persist bodies |
| **Debugging and crash reporting** | Never attach debuggers or crash reporters (Sentry and similar) to production; do not enable `debug`/`trace` logging in production |
| **tmpfs** | Docker `tmpfs` mounts are RAM-backed but **can be swapped**. tmpfs alone does not guarantee that data never reaches disk |
| **Logs** | CipherDrop's logs contain no sensitive values, but the proxy's access logs may contain share ids. Use a privacy log format |

Note that the server only ever holds ciphertext. These measures limit residual ciphertext and metadata; they do not protect keys, which the server never has.

## Native TLS

```toml
[server]
listen = "0.0.0.0:8443"
public_url = "https://paste.example.com:8443"

[server.tls]
cert_path = "/etc/cipherdrop/tls/fullchain.pem"
key_path  = "/etc/cipherdrop/tls/privkey.pem"
```

TLS uses rustls (TLS 1.2 and 1.3, the ring provider). Certificates are loaded at startup; restart to rotate them.

## Graceful shutdown

On `SIGTERM` or `SIGINT`, CipherDrop stops accepting connections, waits up to `shutdown_grace_seconds` for in-flight requests, and exits. In-memory shares are discarded and never persisted.

## Health checks

- `GET /healthz`: the process is alive.
- `GET /readyz`: storage is usable (pings SQLite when configured).
- Both are exempt from the HTTPS requirement so that orchestrators can probe over the internal network.

## Reproducible builds and releases

- `Cargo.lock` and `package-lock.json` are committed; CI uses `cargo --locked` and `npm ci`.
- The toolchain is pinned in `rust-toolchain.toml`.
- Release images are built by GitHub Actions for amd64 and arm64, with an SBOM (`syft`) and a keyless signature (`cosign`).
