# Changelog

## Unreleased

- **Server-enforced share password.** Password-protected shares now carry an `access_verifier`; the server releases ciphertext only for the matching `access_key` (derived from the link key and the password, so the server never learns the password). Wrong passwords consume nothing; shares are destroyed after `shares.max_access_failures` failures. Supported in the web UI, CLI and the Rust, TypeScript/JavaScript and Python SDKs.
- **Connection hardening.** New accept loop with header-read/idle and TLS handshake timeouts, global and per-IP connection caps, and a per-client in-flight request cap (fixes slowloris and slot exhaustion found in the audit).
- Swagger UI page served with a stricter CSP.
- Web UI redesigned to be minimal: one centered column, no icons or effects, ~32 KB gzip JS; Argon2 and documentation are loaded on demand.
- CI actions pinned to commit SHAs with `persist-credentials: false`; base images pinned by digest.
- See `SECURITY_AUDIT.md`.

## 0.1.0 (unreleased)

Initial release.

- Protocol v1: AES-256-GCM, optional Argon2id + HKDF password protection, canonical AAD, padded JSON payload, cross-language test vectors.
- Server: RAM-only sharded store with atomic consumption and an expiry heap; optional SQLite persistence; scoped API tokens; rate limiting; idempotency; RFC 9457 errors; OpenAPI; Prometheus metrics; strict security headers; embedded web UI and documentation.
- Clients: Rust SDK, TypeScript/JavaScript SDK, Python SDK, CLI; PowerShell, C#, Bash and cURL examples.
- Deployment: 12 MB scratch-based multi-arch image, Compose with Caddy, Nginx/Traefik/systemd examples.
