# Architecture

```text
cipherdrop/
├── crates/protocol   Wire protocol v1: API types, envelope validation, AAD, links, client crypto (feature "crypto")
├── crates/storage    MemoryStore (RAM-only, default) and PersistentStore (SQLite, opt-in)
├── crates/server     Axum HTTP server, auth, rate limiting, security headers, embedded web UI, OpenAPI
├── crates/sdk        Rust SDK (reqwest + rustls/ring)
├── crates/cli        `cipherdrop` CLI (clap)
├── sdk/typescript    TypeScript/JavaScript SDK (Web Crypto + hash-wasm Argon2id); also used by the web UI
├── sdk/python        Python SDK (`cryptography`)
├── frontend          Svelte 5 + Vite web interface and documentation site (renders docs/*.md at build time)
├── docs              Documentation (single source for GitHub and /docs)
├── examples          Python, PowerShell, C#, JavaScript, Rust, Bash, cURL
├── tests/e2e         Playwright browser tests
└── deploy            Caddy, Nginx, Traefik, systemd
```

## Request path

```text
TCP accept loop (global + per-IP connection caps, TLS handshake and header-read timeouts)
    → (TLS: rustls | trusted reverse proxy) → edge middleware
      ├─ concurrency semaphore (try_acquire → 503, no queue) + per-client in-flight cap (429)
      ├─ client IP / scheme resolution (trusted proxies only)
      ├─ HTTPS enforcement, Origin validation for unsafe methods
      ├─ request timeout
      └─ security headers, cache policy, sanitized log line
   → router (/api/v1, /healthz, /readyz, /metrics, SPA routes, embedded assets)
   → extractors: Principal (bearer token, per-token rate limit), StrictJson (content type, size, schema)
   → handlers → MemoryStore | PersistentStore (spawn_blocking)
```

## Key decisions

| Decision | Rationale |
|---|---|
| **Key = random 256-bit value in the URL fragment**; no server-side key material | Zero-knowledge by construction; fragments are not sent by browsers |
| **AAD is a canonical ASCII string** | Trivially reproducible in every language; binds all public parameters |
| **Password = Argon2id + HKDF(K ‖ PWK)** | Password supplements, never replaces, the random key |
| **Plaintext is JSON with space padding** | Extensible metadata, all encrypted; padding is valid JSON whitespace |
| **Single protocol crate shared by server/SDK/CLI** | One source of truth; server uses it without the `crypto` feature |
| **Sharded `Mutex<HashMap>` (64 shards)** | Consumption needs check+decrement+remove atomically for one key; a per-shard mutex makes that trivially linearizable. Benchmarks: ~10 ns status, ~18 ns consume, ~355 ns insert+consume (1 KiB) |
| **Lazy-deletion expiry min-heap with compaction** | O(k log n) reclamation of k expired entries; no periodic full scans; heap bounded to O(live) |
| **Global accounting mutex, reject when full** | Exact budgets without eviction surprises |
| **No tombstones; uniform 404** | No metadata retained about consumed/revoked shares; no oracle |
| **Server-enforced password via access key** = HKDF-Expand(PRK(K ‖ Argon2id(pw)), "cipherdrop/v1/access") | Stops link holders from burning password shares and bounds online guessing, while the server never learns the password and cannot attack the verifier offline (needs K) |
| **Own accept loop (hyper-util + tokio-rustls)** instead of `axum::serve`/axum-server | Neither bounds connections or header-read time by default (slowloris, found in the audit) |
| **POST + JSON content type for consume** | Defeats link scanners, prefetchers and simple-request CSRF |
| **SQLite via rusqlite (bundled), single connection, `BEGIN IMMEDIATE`** | Simple, transactional counters; no external service; persistent path is fully separate |
| **SHA-256 verifiers for API/revocation tokens** | Tokens have 256-bit entropy; slow hashing adds no security |
| **Logs record route templates, never URIs** | Share ids never reach logs (tested) |
| **Frontend embedded via rust-embed** | One binary, one container; no CDN |
| **Docs rendered at build time from repository Markdown** | No Markdown parser or raw HTML at runtime |
| **Swagger UI bundled, "Try it out" disabled; encrypting playground instead** | Raw requests would bypass client-side encryption |
| **No browser storage** | Nothing to leak from disk-backed browser storage |
| **Static musl binary on `scratch`, UID 65532** | 12 MB image, no shell, no package manager |

## Not implemented (v0.1.0)

- Eviction policies (`reject_when_full = false` is rejected at startup by design).
- File attachments (text payloads only).
- OIDC / user accounts (scoped API tokens only).
- Fuzzing runs in CI require nightly; `fuzz/` targets are provided, and property tests run on stable.
- Per-token daily quotas reset on restart (in-memory counters).
