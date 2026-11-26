# CipherDrop security audit — 2026-11-26

> **Internal audit, not independent.** Performed by the development team's AI assistant using the
> [claude-red](https://github.com/SnailSploit/claude-red) offensive-security methodology (installed locally, not part of this repository),
> plus white-box code review. It is not a substitute for an independent third-party audit.

## Executive summary

The web application and REST API were tested white-box and black-box against local instances. The core cryptographic design (client-side AES-256-GCM, fragment-only keys, AAD binding, atomic consumption) held up: no confidentiality or integrity issue was found.

Seven issues were found. All are fixed and retested:

- **One business-logic flaw (Medium).** Anyone holding the link could burn a password-protected share without knowing the password.
- **Two availability flaws (High and Medium).** Slowloris-style connection exhaustion, and one client able to occupy every request slot.
- **Four lower-severity hardening and supply-chain items.**

The business-logic fix also delivers a new feature: **the share password is now enforced by the server**, without the server ever learning it.

| ID | Title | Severity | Status |
|---|---|---|---|
| CD-01 | Password-protected share could be burned without the password | Medium (CVSS 5.3) | **Fixed** |
| CD-02 | No header-read/idle timeout and no connection caps (slowloris, fd exhaustion) | High (CVSS 7.5) | **Fixed** |
| CD-03 | Single client could occupy all global request slots | Medium (CVSS 5.3) | **Fixed** |
| CD-04 | API explorer CSP broader than needed (`wasm-unsafe-eval`) | Low | **Fixed** |
| CD-05 | CI actions pinned to mutable tags/branch; checkout persisted the token | Low | **Fixed** |
| CD-06 | Container base images not pinned by digest | Low | **Fixed** |
| CD-07 | Unmaintained dependency `humantime` (RUSTSEC-2026-0542) | Info | **Fixed** |
| CD-08 | Exact version disclosed by `/api/v1/version` | Info | Accepted |
| CD-09 | Link holder can deliberately destroy a password share via failed attempts | Info | Accepted (design trade-off) |

Retest: **68/68 black-box checks pass** (62 functional, 2 rate-limit, 4 DoS), along with all unit, integration, property, browser E2E and cross-language suites.

## Scope

- `cipherdrop-server` (API `/api/v1`, static web UI, docs, Swagger UI, health, metrics), memory and SQLite backends, the native TLS listener.
- Web UI (Svelte), TypeScript/JavaScript SDK as used by the UI.
- Container image, Compose stack, CI workflows, dependency supply chain.
- Out of scope: production infrastructure, independent cryptanalysis of the primitives, browser and OS vulnerabilities.

## Method

- **Playbooks used** (claude-red): `offensive-api-security`, `offensive-api-abuse`, `offensive-business-logic`, `offensive-race-condition`, `offensive-crypto-attacks`, `offensive-xss`, `offensive-cicd-pipeline`, `offensive-supply-chain`, `offensive-container-escape`, `offensive-reporting`.
- **White-box review:** request path, extractors, auth and scopes, storage atomicity, the serve loop, CSP and headers, frontend rendering, CI and Dockerfile.
- **Black-box harness:** `tests/security/attack.py` and `tests/security/dos.py`, run against release builds on loopback:
  - `:18100`: production-like, rate limits on, persistent storage and tokens enabled.
  - `:18101`: limits relaxed, used for race and logic tests.
  - `:18102`: listening on all interfaces, so DoS probes can come from a second source IP.
- **Tooling:** `cargo audit`, `cargo deny`, `npm audit`, Playwright (CSP-violation, storage and request inspection).

## Findings

### CD-01 — Password-protected share could be burned without the password

**Severity:** Medium (CVSS 3.1 5.3, AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L) · **CWE-840** (business logic), CWE-285 · **Status:** Fixed

**Description.** The password was a purely client-side decryption factor. The server released the ciphertext to any consume request, so anyone holding the link without the password could consume a one-time share and deny it to the intended recipient. They could also take the ciphertext for offline guessing.

**Reproduction (before).** Create a password share with `max_reads = 1`, then `POST /api/v1/shares/{id}/consume` with `{}`. The response was `200` with ciphertext, and status then returned `404`. Harness: `LOGIC-1  consume=200 then status=404`.

**Remediation.** A server-enforced access key:
- One Argon2id evaluation yields `PRK = HKDF-Extract(salt, K ‖ PWK)`. From it, `CEK = Expand(PRK, "cipherdrop/v1/cek/password")` and `access_key = Expand(PRK, "cipherdrop/v1/access")`.
- At creation the client uploads `SHA-256(access_key)` (`access_verifier`, now **mandatory** for KDF shares).
- On consume the server compares in constant time, inside the same lock or transaction that decrements the counter.
- Wrong or missing keys return `403 access_denied` and consume nothing. After `max_access_failures` (default 10) the share is destroyed (`410`).
- The server never sees the password and cannot attack the verifier offline without the 256-bit `K`.
- Implemented in the protocol, both storage backends, the server, all SDKs, the CLI and the web UI, with test vectors.

**Retest.** `LOGIC-0` (ungated password share refused, 400), `LOGIC-1` (no-key 403, wrong-key 403, remaining 1), `LOGIC-2` (10 failures, then 410, then 404) all pass. Covered by the Rust and Playwright tests.

### CD-02 — No header-read/idle timeout and no connection caps

**Severity:** High (CVSS 3.1 7.5, AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H) · **CWE-400**, CWE-770 · **Status:** Fixed

**Description.** `axum::serve` exposes no header-read timeout, and axum-server explicitly disables hyper's (`header_read_timeout(None)`). Neither bounds connection count. An unauthenticated client could hold unlimited half-open or idle connections until file descriptors ran out.

**Reproduction (before).** 1500 sockets sending `GET /healthz HTTP/1.1\r\nHost: x\r\n` and never finishing: `0/1500` were closed after 36 s (`DOS-2`). 50 idle keep-alive connections: `0/50` closed after 70 s (`DOS-3`).

**Remediation.** A new accept loop (`crates/server/src/serve.rs`, hyper-util plus tokio-rustls) used for both plain TCP and native TLS. It applies:
- `max_connections` (4096);
- `max_connections_per_ip` (64), with trusted proxies exempt;
- `header_read_timeout_seconds` (10), which also covers idle keep-alive;
- a 10 s TLS handshake timeout;
- HTTP/2 keep-alive pings and a 64-stream limit.

**Retest.** `DOS-1` (other clients served while one IP holds 1500 half-open connections), `DOS-2` (1500/1500 reaped) and `DOS-3` (50/50 closed) all pass. Covered by the `crates/server/tests/connections.rs` test.

### CD-03 — Single client could occupy all global request slots

**Severity:** Medium (CVSS 3.1 5.3) · **CWE-770** · **Status:** Fixed

**Description.** The global concurrency limit (256) was shared by all clients. One client opening 300 slow uploads held every slot for up to `request_timeout_seconds`, so everyone else got `503`.

**Reproduction (before).** 300 connections each sending headers plus 1 byte of a 100 kB body; a concurrent `GET /api/v1/config` got `503` (`DOS-4`).

**Remediation.** A per-client in-flight cap, `max_concurrent_requests_per_ip` (32, keyed like the rate limiter, `/64` for IPv6), combined with the per-IP connection cap from CD-02.

**Retest.** `DOS-4` passes: other clients get `200` while one IP holds 300 slow uploads.

### CD-04 — API explorer CSP broader than needed

**Severity:** Low · **CWE-1021** (defence in depth) · **Status:** Fixed

`/docs/api/explorer` (Swagger UI) shared the SPA's CSP, which includes `'wasm-unsafe-eval'` for Argon2. It now gets a dedicated `EXPLORER_CSP` without it. Retest: `HDR-3` passes, and the Playwright run records no CSP violations.

### CD-05 — CI actions on mutable references; persisted credentials

**Severity:** Low · **CWE-829**, CWE-1357 · **Status:** Fixed

Workflows referenced third-party actions by tag (one by `@master`), and `actions/checkout` left the token in `.git/config`. All actions are now pinned to full commit SHAs (tag kept as a comment for Dependabot), with `persist-credentials: false`.

### CD-06 — Base images not pinned by digest

**Severity:** Low · **CWE-829** · **Status:** Fixed

`node`, `rust`, `alpine` and `caddy` images are now pinned by `@sha256:` digest. Dependabot (docker ecosystem) keeps them updated.

### CD-07 — Unmaintained dependency

**Severity:** Info · **Status:** Fixed. `humantime` (RUSTSEC-2026-0542) was replaced with a strict duration parser in the CLI. `cargo audit` and `cargo deny` are clean.

### CD-08 — Version disclosure

**Severity:** Info · **Status:** Accepted. `/api/v1/version` returns the exact version, which clients need for protocol negotiation. The code is open source, so this adds little for an attacker.

### CD-09 — Deliberate destruction via failed attempts

**Severity:** Info · **Status:** Accepted. Someone with the link but not the password can destroy a password share by failing `max_access_failures` times. This is the deliberate trade-off against unbounded online guessing; before CD-01 was fixed, the same person could simply consume the share. Operators can raise the budget.

## Checks that passed (no finding)

- **Authn/authz:** malformed, unknown or tampered bearer tokens get `401` and are never downgraded to anonymous. A token without `admin:manage` gets `403` on admin endpoints (BFLA). Anonymous callers can't create persistent or never-expiring shares.
- **Mass assignment** (`id`, `revocation_token`, `remaining_reads`, `created_at`, `expires_at`, `owner`): rejected.
- **Parameter pollution and type confusion:** duplicate JSON keys, overflowing integers, floats, strings-for-numbers and padded base64 are rejected.
- **Content-type switching** (form, multipart, XML, text, json-patch): `415`. 5000-level JSON nesting: `400`. A 3 MB body is rejected from `Content-Length`, before it is read.
- **Verb tampering** (`PUT`/`PATCH`/`GET`/`HEAD`/`OPTIONS`/`TRACE` on `/consume`) and `X-HTTP-Method-Override`: never consume.
- **Path traversal** (`%2e%2e`, `..%2f`, double encoding, NUL) on `/assets` and `/swagger`: blocked.
- **Host / X-Forwarded-Host injection:** share URLs always come from the configured `public_url`.
- **CORS and CSRF:** no CORS grant for foreign origins. Cross-origin consume with `Origin`, `Origin: null` or `Sec-Fetch-Site: cross-site` gets `403`. Simple (preflight-free) requests get `415`.
- **Races:**
  - 100-way single-burst consume of a one-time share: exactly one `200`, over 10 rounds.
  - 64-way burst on a 10-read share: each counter value observed exactly once.
  - Consume vs revoke: exactly one wins, over 20 rounds.
  - 30-way idempotency-key burst: one share created.
- **Rate limits:** spoofed `X-Forwarded-For`, `X-Real-IP` and `True-Client-IP` don't bypass the per-IP limits.
- **Crypto (white-box):**
  - random 96-bit nonces under single-use keys (no reuse);
  - AAD binds version, algorithm and KDF parameters, so downgrades fail;
  - Argon2id bounded on both sides;
  - constant-time verifier comparisons;
  - no padding or decryption oracle (the server never decrypts).
- **XSS:** content and titles render as text. A `<script>`/`onerror` payload stays inert in the browser, with zero CSP violations (Playwright). Docs HTML is build-time only, with raw HTML escaped.
- **Logs and storage:** no ids, URLs, tokens, ciphertext, keys or IPs in logs, even at TRACE. RAM-only mode writes no files. Ephemeral ciphertext never reaches SQLite.
- **Browser:** no `localStorage`/`sessionStorage`/IndexedDB/cookies/service workers, and no external requests. The key never appears in any request URL, body or header, and neither does the password.

## Residual risks and limitations

- This is an internal audit by the development team's tooling: **not independent**.
- Browser E2EE trusts the server to deliver honest JavaScript (documented; prefer the CLI or SDKs where that matters).
- Fuzzing targets exist (`fuzz/`) but were not run (they need a nightly toolchain). Property-based tests cover the storage engine and protocol parsers.
- DoS testing was single-host and loopback-only; volumetric attacks need upstream protection.
- Per-token daily quotas are in memory and reset on restart (documented).
- An attacker who obtains both the link and the ciphertext (e.g. a compromised operator who also intercepts links) can guess the password offline, slowed only by Argon2id.

## Notes for retest

See `tests/security/README.md`. Re-run all three harness invocations after changes to the serve loop, extractors, storage or middleware.
