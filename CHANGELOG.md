# Changelog

## Unreleased

## 0.1.0 (2026-11-27)

First public release.

- Protocol v1: AES-256-GCM, optional Argon2id + HKDF password protection, canonical AAD, padded JSON payload, cross-language test vectors.
- Server: RAM-only sharded store with atomic consumption and an expiry heap; optional SQLite persistence; scoped API tokens; rate limiting; idempotency; RFC 9457 errors; OpenAPI; Prometheus metrics; strict security headers; embedded web UI and documentation.
- Clients: Rust SDK, TypeScript/JavaScript SDK, Python SDK, CLI; PowerShell, C#, Bash and cURL examples.
- Deployment: 12 MB scratch-based multi-arch image, Compose with Caddy, Nginx/Traefik/systemd examples.

### Since the initial development snapshot

- **Server-enforced share password.** Password-protected shares now carry an `access_verifier`; the server releases ciphertext only for the matching `access_key` (derived from the link key and the password, so the server never learns the password). Wrong passwords consume nothing; shares are destroyed after `shares.max_access_failures` failures. Supported in the web UI, CLI and the Rust, TypeScript/JavaScript and Python SDKs.
- **Connection hardening.** New accept loop with header-read/idle and TLS handshake timeouts, global and per-IP connection caps, and a per-client in-flight request cap (fixes slowloris and slot exhaustion found in the audit).
- Swagger UI page served with a stricter CSP.
- Web UI redesigned to be minimal: one centered column, no icons or effects, ~32 KB gzip JS; Argon2 and documentation are loaded on demand.
- CI actions pinned to commit SHAs with `persist-credentials: false`; base images pinned by digest.
- See `SECURITY_AUDIT.md`.
- **Production deployment** (`deploy/production/`, `.github/workflows/release.yml`). One `install.sh` sets up a Debian/Ubuntu host behind an existing reverse proxy. It installs Docker and a pinned cosign, adds a read-only deploy key and an Actions-read token, picks a free Docker subnet and generates nginx, Caddy, Apache and Traefik configurations. A systemd timer runs `cipherdropctl update`, which deploys each successful `v*` release. The tag's commit must match the run, the image archives must match a Sigstore-signed SHA256SUMS bound to the exact tag and commit, and the release must pass config, health, version and public smoke checks. Otherwise it rolls back automatically and skips the release. Also includes notifications, pause/resume, rollback, API token management and an operator runbook. Releases now attach per-architecture image archives to the workflow run.
- **Deployment modes.** `install.sh --mode local|remote|caddy`. `local`: the reverse proxy is on this host (`127.0.0.1:PORT`). `remote`: the reverse proxy is on another server (e.g. nginx `proxy_pass` to `THIS-HOST-IP:PORT`); only `--proxy-ip` is trusted for forwarded headers, and an iptables `DOCKER-USER` rule (reapplied at boot by `cipherdrop-firewall.service`) drops other sources. `caddy`: no external proxy; the bundled Caddy serves HTTPS on 80/443 with automatic certificates. The port is selectable (`--port`) and checked for conflicts. Re-running the installer with new options applies them and restarts the service.
