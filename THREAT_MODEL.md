# CipherDrop threat model

Status: design-level threat model for v0.1.0. CipherDrop has **not** been independently audited.

## Assets

| Asset | Where it exists |
|---|---|
| Plaintext (content, title, syntax) | Sender and recipient devices only |
| Share key `K` | Sender/recipient memory, the share link (URL fragment), wherever the link is pasted |
| Optional password | Sender/recipient memory, out-of-band channel |
| Ciphertext envelope | Server RAM (default) or SQLite (explicitly persistent shares); in transit over TLS |
| Revocation token | Creator; server holds only SHA-256 verifier |
| API tokens | Token holders; server holds only SHA-256 verifiers |
| Operational metadata (id, times, read counter, size, password flag) | Server |

## Trust boundaries and actors

1. **Network attacker** (passive/active, without TLS keys).
2. **Honest-but-curious server operator / host** (reads RAM, disk, logs, backups).
3. **Malicious or compromised server** (modifies responses or served code).
4. **Unauthorized third party** who obtains a share id, a full link, or a revocation link.
5. **Link scanners, crawlers and preview bots**.
6. **Malicious API clients** (resource exhaustion, enumeration, CSRF, injection).
7. **Compromised endpoint** (malware, extensions) on the sender or recipient device.

## Threats, mitigations and residual risk

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | Server/DB/backup reads secrets | Client-side AES-256-GCM; key only in fragment; server has no decryption code path for content | Ciphertext length (256-byte buckets), timing, IPs visible |
| T2 | Network attacker reads/modifies traffic | HTTPS required by default (TLS or trusted proxy), HSTS, GCM authentication + AAD | Misconfigured proxies; users ignoring certificate errors |
| T3 | Malicious server serves backdoored JS | None possible within browser E2EE; documented; CLI/SDKs as independently distributed clients; CSP limits third-party injection | **Full compromise of browser users** if the origin is malicious |
| T4 | Server tampers with envelope (KDF downgrade, nonce swap) | AAD binds version, algorithm and all KDF parameters; KDF bounds enforced client-side | None known |
| T5 | Brute-force of share ids | 128-bit random ids; uniform 404; per-IP rate limits | None practical |
| T6 | Offline guessing of share key | 256-bit random key | None practical |
| T7 | Offline guessing of password (attacker has full link + ciphertext) | Argon2id (≥19 MiB, ≥2 passes) + HKDF with random key | Weak passwords remain guessable |
| T7b | Online guessing / burning of a password share by a link holder | Server-enforced access key (derived from K + password) checked atomically before release; wrong keys consume nothing; share destroyed after `max_access_failures` | A link holder can deliberately destroy a password share by failing repeatedly |
| T8 | Double reveal of one-time share (race) | Atomic check-and-decrement under one shard lock / `BEGIN IMMEDIATE` transaction; tested with 100 concurrent consumers | None known |
| T9 | Link scanners burn secrets | GET/HEAD never consume; consume needs POST + `application/json` + explicit click; `noindex`, `robots.txt`, no preview metadata | Bots that execute JS and click buttons |
| T10 | CSRF: foreign site burns a share | Non-simple request required (preflight); CORS denied by default; `Origin`/`Sec-Fetch-Site` validation | Requires attacker to know the share id anyway |
| T11 | XSS via shared content | Content rendered as text or via escaping highlighter; strict CSP without `unsafe-inline`; no raw HTML in docs | Browser bugs |
| T12 | Key leaks via Referer, logs, history | Fragment never sent; `Referrer-Policy: no-referrer`; logs contain route templates only (tested); fragment stripped from history on reveal | History/sync/extensions that recorded the URL before reveal |
| T13 | Resource exhaustion | Connection caps (global and per IP), header-read, keep-alive and TLS-handshake timeouts, per-client in-flight cap, body limit, ciphertext limit, memory and share-count budgets (reject, never evict), concurrency limit with load shedding, timeouts, rate limits, bounded idempotency cache, KDF upper bounds | Volumetric DDoS needs upstream protection |
| T14 | Forged `X-Forwarded-For` to evade limits | Forwarded headers honoured only from configured trusted proxies; right-most untrusted hop used | Misconfigured `trusted_proxies` |
| T15 | Host header injection into links | Links built only from configured `public_url` | None |
| T16 | Persistent data remanence | RAM-only default; persistent opt-in only with scope; `secure_delete`; ids stored hashed; 0600 file | SSD/FS journals, snapshots, backups (documented) |
| T17 | RAM remanence to disk (swap, dumps) | Core dumps disabled, `PR_SET_DUMPABLE=0`, optional `mlockall`, deployment guidance (no swap, no hibernation, no checkpoints) | Host/hypervisor-level snapshots |
| T18 | Stolen API token | SHA-256 verifiers, scopes, expiry, revocation, per-token rate limits and quotas | Token valid until revoked/expired |
| T19 | Stolen revocation link | Only allows deletion (availability), not decryption | Creator's share can be deleted |
| T20 | Admin abuse | Admins can revoke and manage tokens but cannot decrypt | Admins can deny service |
| T21 | Supply chain | Lockfiles, `cargo audit`, `cargo deny`, `npm audit`, install scripts disabled, no CDN, SBOM, signed images | Compromised upstream releases |
| T22 | Endpoint compromise | Out of scope | Full compromise |
| T23 | Lost one-time secret (network failure after consume) | No automatic retries; documented | Secret lost; sender must re-share |

## Explicit assumptions (unverified)

- The OS CSPRNG, AES-GCM, Argon2id and HKDF implementations in the dependencies (RustCrypto, Web Crypto, hash-wasm, `cryptography`, .NET) are correct.
- Browsers do not transmit URL fragments in requests (standard behaviour).
- TLS is correctly configured by the operator.
- Best-effort zeroization: not guaranteed by compilers, allocators, JavaScript engines or the OS.

## Out of scope

Endpoint security, traffic analysis resistance, anonymity of users, deniability, protection against a malicious origin serving modified web code, and availability against large-scale DDoS.
