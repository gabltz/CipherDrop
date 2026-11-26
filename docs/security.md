# Security model

This page summarizes CipherDrop's security properties. The full threat model is in `THREAT_MODEL.md` at the repository root. CipherDrop has **not** been independently audited. Evaluate it against your own requirements.

## Properties

| Property | Mechanism |
|---|---|
| Confidentiality against the server operator, database leaks and network observers | Client-side AES-256-GCM; key only in the URL fragment |
| Integrity of content and parameters | GCM authentication tag over ciphertext plus AAD binding version, algorithm and KDF parameters |
| Single use | Atomic check-and-decrement under one lock (RAM) or one `BEGIN IMMEDIATE` transaction (SQLite) |
| Bounded exposure in time | Mandatory expiry by default, plus read-time expiry checks and background reclamation |
| No disk residue (default mode) | RAM-only store with no persistence code path; no temporary files |
| Password enforced before release | Clients prove knowledge of the password with an access key derived from `K` and the password; the server checks it in constant time inside the atomic consume and never learns the password. Wrong passwords consume nothing; repeated failures destroy the share |
| Connection-level DoS resistance | Global and per-IP connection caps, a header-read timeout that also reaps idle keep-alive connections, a TLS handshake timeout, and a per-client in-flight request cap |
| Revocation | Per-share 256-bit revocation token (SHA-256 verifier stored), or the `shares:revoke` scope |
| Resistance to enumeration | 128-bit random share ids, uniform `404` for all unavailable states, per-IP rate limits |
| Scanner and preview safety | Opening a page never consumes; consume requires `POST` plus a JSON content type |
| CSRF resistance | Consume, create and revoke require non-simple requests; foreign `Origin` headers are rejected |

## What the server operator can and cannot do

An honest-but-curious or compromised **server** (database, memory dump, logs) learns ciphertext, its length, timing, client IPs, and whether a password was used. It cannot decrypt shares.

An **actively malicious** server can do much more to **browser** users, because it serves the JavaScript that performs encryption.

### Trusting the web client

Browser-based end-to-end encryption assumes the code you run is the code you expect. A malicious or compromised server, or anyone who can modify its responses, can serve JavaScript that exfiltrates plaintext or keys. Content Security Policy, Subresource Integrity and HTTPS do not defend against the origin itself.

Stronger options:

- Use the **CLI or an SDK**: their code is distributed independently, can be pinned, reviewed and reproducibly built, and does not change per request.
- Self-host, and build the image from source you have reviewed.
- Compare the served bundle hash with a release build (the frontend build is deterministic for a given lockfile).

## Limitations you should know about

- **Whoever holds the complete link can decrypt.** Links are capabilities. Chat apps, email gateways, ticket systems and clipboard managers may store them.
- **Link scanners that act like browsers.** Security gateways that render pages and click buttons could trigger a reveal. CipherDrop cannot distinguish an automated client that deliberately calls `POST /consume` from a human.
- **Browser history.** The browser records the full URL, fragment included, when a link is opened. CipherDrop replaces the current history entry with a fragment-free URL when you click *Reveal*, but synced history, other tabs and extensions may already have seen it.
- **Browser extensions** with page access can read keys and plaintext.
- **Endpoint compromise** (malware, keyloggers, screen capture) defeats any client-side encryption.
- **Clipboard.** Copied secrets stay in the clipboard and in clipboard history tools.
- **Memory erasure is best effort.** The server wipes ciphertext buffers on deletion and clients wipe key buffers. Allocators, the JavaScript garbage collector, swap, hibernation files and hypervisor snapshots can still retain copies. See [Deployment](deployment.md#keeping-secrets-out-of-persistent-storage).
- **Password strength.** Online guessing by a link holder is limited by `max_access_failures`, after which the share is destroyed. An attacker who has the link *and* a copy of the ciphertext (e.g. a compromised server operator who also obtained the link) can guess offline, slowed only by Argon2id.
- **Metadata.** Timing, sizes (to 256 bytes), IP addresses at the network level, and the fact that a share exists are visible to the server and to network observers.
- **Lost responses.** A consume whose response is lost (network failure) still counts. A one-time secret can be lost this way.
- **Persistent storage deletion.** Deleting a persistent share does not guarantee physical erasure from SQLite free pages, journals, filesystem journals, SSD wear-levelling, snapshots or backups. CipherDrop enables SQLite `secure_delete`, which is best effort only.
- **Ciphertext is not verified.** The server cannot prove an API caller encrypted anything.

## Hardening built in

- Content Security Policy without `unsafe-inline` or `unsafe-eval` (only `wasm-unsafe-eval` for the bundled Argon2id module, and not even that on the API explorer page), `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'none'`.
- `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a restrictive `Permissions-Policy`, `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`, HSTS when HTTPS is required.
- `Cache-Control: no-store` on all API and HTML responses; `X-Robots-Tag: noindex` and `robots.txt` disallowing all crawling; no Open Graph metadata, so link previews show nothing.
- Strict JSON parsing (unknown fields rejected), body size limits, request timeouts, a global concurrency limit with load shedding, a memory budget, and a share-count cap.
- Public URLs come from configuration, never from the `Host` header.
- `X-Forwarded-*` headers are honoured only from configured trusted proxies; the client IP is the right-most untrusted hop.
- API tokens and revocation tokens are stored as SHA-256 verifiers and compared in constant time.
- Logs contain only method, route template, status and latency. They never contain bodies, ids, URLs, tokens, authorization headers or IP addresses. This is covered by an automated test.
- Metrics use a fixed label set with no identifiers.
- Process hardening: core dumps disabled (`RLIMIT_CORE=0`; `PR_SET_DUMPABLE=0` on Linux), optional `mlockall`.
- No browser storage: the web client uses no `localStorage`, `sessionStorage`, IndexedDB, cookies or service workers. API tokens entered in the UI live only in tab memory.
- No external requests: fonts, icons, Swagger UI and WebAssembly are all bundled.

## Audit history

An internal white-box and black-box audit (not independent) was carried out on 2026-11-26. The findings and fixes are in `SECURITY_AUDIT.md` at the repository root.

## Reporting vulnerabilities

See `SECURITY.md`.
