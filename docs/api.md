# API reference

All web interface operations use this same public, versioned API. The machine-readable specification is served at [`/api/v1/openapi.json`](/api/v1/openapi.json) and rendered by the bundled [API explorer](/docs/api/explorer).

> The API never accepts plaintext. Every client must encrypt locally ([Encryption protocol](encryption.md)) and send only the envelope. The server cannot verify that a payload is really encrypted; a client that uploads plaintext defeats its own confidentiality.

## Conventions

- Base path: `/api/v1`. Breaking changes will use a new prefix (`/api/v2`); v1 stays stable.
- Request and response bodies are JSON (`Content-Type: application/json`). Unknown request fields are **rejected**.
- Binary values use unpadded base64url (RFC 4648 §5).
- Timestamps are RFC 3339 UTC strings.
- Errors use RFC 9457 Problem Details (`application/problem+json`) with a stable `code`.
- Every response carries `Cache-Control: no-store` unless it is a static asset.

## Authentication

Send an API token as a bearer token:

```http
Authorization: Bearer cdt_4f1c2a9b7e30_Hq3fV0...
```

A request with an **invalid** token is rejected with `401`; it is never downgraded to anonymous.

| Scope | Grants |
|---|---|
| `shares:create` | Create shares (memory storage, finite expiry) |
| `shares:create:persistent` | Create `storage: "persistent"` shares and shares that never expire (if enabled) |
| `shares:consume` | Retrieve shares and query status when `anonymous_retrieval = false` |
| `shares:revoke` | Revoke **any** share without its revocation token |
| `admin:metrics` | Read `/metrics` |
| `admin:manage` | Manage API tokens |

Deployment modes:

| Mode | `anonymous_creation` | `anonymous_retrieval` |
|---|---|---|
| Public pastebin | `true` | `true` |
| Authenticated creation, capability-link retrieval (default) | `false` | `true` |
| Fully authenticated | `false` | `false` |
| Admin-only permanent shares | any | any; grant `shares:create:persistent` only to administrators |

Administrators can revoke shares and manage tokens, but can never decrypt: the server does not have the keys.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/shares` | Create an encrypted share |
| `POST` | `/api/v1/shares/{id}/consume` | Atomically consume one retrieval and return ciphertext |
| `GET` | `/api/v1/shares/{id}/status` | Non-consuming status |
| `DELETE` | `/api/v1/shares/{id}` | Revoke a share |
| `GET` | `/api/v1/config` | Public instance capabilities and limits |
| `GET` | `/api/v1/version` | Server version and protocol versions |
| `GET` | `/api/v1/openapi.json` | OpenAPI document |
| `POST` / `GET` | `/api/v1/admin/tokens` | Create / list API tokens (`admin:manage`) |
| `DELETE` | `/api/v1/admin/tokens/{id}` | Revoke an API token (`admin:manage`) |
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness (checks SQLite when configured) |
| `GET` | `/metrics` | Prometheus metrics (disabled by default; `admin:metrics`) |

### Create a share

```http
POST /api/v1/shares
Content-Type: application/json
Idempotency-Key: 6f1e0c8a-retry-safe      (optional)

{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "nonce": "AAECAwQFBgcICQoL",
  "ciphertext": "PCC1dKuRp3X5Y62p-YwUAez6p3eZCzcZSiOX6m1IIs-3N7ok3JAc-jf2ZFEUq-Y6",
  "ttl_seconds": 3600,
  "max_reads": 1,
  "storage": "memory"
}
```

| Field | Rules |
|---|---|
| `version` | Must be `1` |
| `algorithm` | Must be `"AES-256-GCM"` |
| `nonce` | 12 bytes, base64url (16 chars) |
| `ciphertext` | Ciphertext with appended 16-byte tag; at most `max_ciphertext_bytes` decoded |
| `kdf` | Only for password-protected shares: `{"algorithm":"argon2id","salt":…,"memory_kib":…,"iterations":…,"parallelism":…}` |
| `ttl_seconds` | Omit for the default. `min_ttl_seconds..=max_ttl_seconds`. `null` = never expires (needs `allow_permanent` and `shares:create:persistent`) |
| `max_reads` | Omit for the default. `1..=max_reads`. `null` = unlimited until expiry (needs `allow_unlimited_reads`) |
| `storage` | `"memory"` (default) or `"persistent"` (needs `persistent_enabled` and `shares:create:persistent`) |

Response `201 Created`:

```json
{
  "id": "3q2-7wUb1dEVxG3qkDfN8A",
  "url": "https://paste.example.com/s/3q2-7wUb1dEVxG3qkDfN8A",
  "created_at": "2026-01-01T12:00:00Z",
  "expires_at": "2026-01-01T13:00:00Z",
  "max_reads": 1,
  "storage": "memory",
  "revocation_token": "s9N3u...43 chars",
  "revocation_url": "https://paste.example.com/revoke/3q2-7wUb1dEVxG3qkDfN8A#v1.s9N3u..."
}
```

The `url` never contains a key. The client appends `#v1.<key>` locally. Keep `revocation_token` away from recipients: anyone holding it can delete the share.

### Consume a share

```http
POST /api/v1/shares/{id}/consume
Content-Type: application/json

{}
```

The `Content-Type: application/json` header and the `{}` body are **required**. They make the request "non-simple", so browsers cannot send it cross-site without a CORS preflight, which CipherDrop denies by default.

Response `200 OK`:

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "nonce": "AAECAwQFBgcICQoL",
  "ciphertext": "PCC1dKuRp3X5...",
  "remaining_reads": 0,
  "expires_at": "2026-01-01T13:00:00Z"
}
```

`remaining_reads: 0` means the share was deleted by this request. Unknown, expired, exhausted and revoked shares all return the same `404 share_unavailable`. CipherDrop keeps no tombstones and cannot tell these cases apart.

### Status (non-consuming)

`GET /api/v1/shares/{id}/status` returns `{available, expires_at, remaining_reads, password_protected, storage}` or `404`. It never changes the read counter, so it is safe for monitoring and link checkers.

### Revoke

```http
DELETE /api/v1/shares/{id}
X-Revocation-Token: s9N3u...
```

Or with an API token holding `shares:revoke` (no revocation token needed). Responses: `204` revoked, `403` wrong token, `404` unavailable.

## Errors

```json
{
  "type": "https://cipherdrop.dev/problems/share-unavailable",
  "title": "Share unavailable",
  "status": 404,
  "detail": "The share does not exist, has expired, has already been retrieved the maximum number of times, or was revoked",
  "code": "share_unavailable"
}
```

| HTTP | `code` | Meaning |
|---|---|---|
| 400 | `invalid_request` | Malformed JSON, unknown field, invalid envelope, limits out of range, malformed id |
| 401 | `unauthorized` | Missing or invalid token where one is required |
| 403 | `insufficient_scope` | Token lacks the required scope |
| 403 | `forbidden` | Wrong revocation token, or immutable configuration token |
| 403 | `feature_disabled` | Persistent storage, permanent or unlimited shares disabled |
| 403 | `cross_origin_rejected` | State-changing request from a disallowed `Origin` |
| 403 | `https_required` | Plain HTTP reported by a trusted proxy while HTTPS is required |
| 404 | `share_unavailable` | Unknown, expired, consumed or revoked |
| 404 | `not_found` | Unknown route or token |
| 405 | – | Wrong method (e.g. `GET /consume`) |
| 408 | `timeout` | Request exceeded `request_timeout_seconds` |
| 413 | `payload_too_large` | Ciphertext or body exceeds the limit |
| 415 | `unsupported_media_type` | Missing `Content-Type: application/json` |
| 422 | `idempotency_key_reused` | Same `Idempotency-Key` with a different body |
| 429 | `rate_limited` | Rate limit exceeded (`Retry-After` header) |
| 429 | `quota_exceeded` | Token's daily creation quota exhausted |
| 503 | `overloaded` | Concurrency limit reached (`Retry-After`) |
| 507 | `capacity_exhausted` | Memory or share-count budget exhausted (`Retry-After`). Existing shares are never evicted |

Error bodies never echo request content, identifiers or tokens.

## Rate limits

- Anonymous share creation: `rate_limit.create_per_minute` per client IP (default 30).
- Anonymous consume/status/revoke: `rate_limit.read_per_minute` per client IP (default 120).
- Authenticated requests: per token, `rate_limit_per_minute` on the token or `token_default_per_minute` (default 600).
- IPv6 clients are grouped by `/64` (configurable).
- Client IPs come from the TCP peer unless the peer is a configured trusted proxy (see [Configuration](configuration.md#security)).

## Retry semantics

| Operation | Safe to retry? |
|---|---|
| `GET` endpoints | Yes |
| `POST /shares` without `Idempotency-Key` | Retrying may create a duplicate share (harmless but wasteful) |
| `POST /shares` with `Idempotency-Key` | Yes: within `idempotency_ttl_seconds` an identical body returns the original response |
| `POST /consume` | **No.** Never retry automatically. The first request may have consumed the share even if its response was lost |
| `DELETE /shares/{id}` | Yes: a repeat returns `404` |

Official SDKs and the CLI never retry `consume`.

## Raw cURL with a pre-encrypted payload

cURL cannot encrypt, so you must produce the envelope with a trusted local tool first. A plaintext cURL request is **not** end-to-end encrypted. The example below uses `examples/curl/encrypt.py` (built on the Python SDK), which writes `request.json` and stores the key in a `0600` file:

```bash
printf '%s' "example secret" | python3 examples/curl/encrypt.py --key-file key.txt > request.json
KEY=$(cat key.txt)
curl -sS https://paste.example.com/api/v1/shares \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $CIPHERDROP_API_KEY" \
  --data-binary @request.json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["url"] + "#v1." + sys.argv[1])' "$KEY"
```

Consume (returns ciphertext only):

```bash
curl -sS -X POST https://paste.example.com/api/v1/shares/$ID/consume \
  -H 'Content-Type: application/json' --data '{}'
```

## Interactive playground

The playground below encrypts your input in this browser before sending anything, and shows the exact request body. It is useful for exploring responses and error codes. Use synthetic data.
