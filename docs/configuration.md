# Configuration reference

CipherDrop reads a TOML file (`--config PATH` or `CIPHERDROP_CONFIG`) and then applies environment overrides of the form `CIPHERDROP__<SECTION>__<KEY>`:

```bash
CIPHERDROP__SERVER__PUBLIC_URL=https://paste.example.com
CIPHERDROP__STORAGE__MAX_MEMORY_MB=256
CIPHERDROP__SECURITY__TRUSTED_PROXIES='["10.0.0.0/8"]'     # values are parsed as TOML when possible
```

Unknown keys are rejected. The configuration is validated at startup (`cipherdrop-server check-config`), and the server refuses to start on unsafe or inconsistent settings. Every default is the secure choice.

## `[server]`

| Key | Default | Description |
|---|---|---|
| `listen` | `"127.0.0.1:8080"` | Listen address |
| `public_url` | **required** | Base URL for share links. Share links are never derived from the `Host` header |
| `max_concurrent_requests` | `256` | Requests beyond this get `503` immediately (no unbounded queue) |
| `shutdown_grace_seconds` | `10` | Drain time on `SIGTERM` |
| `tls.cert_path`, `tls.key_path` | none | Enable native HTTPS (PEM) |

## `[storage]`

| Key | Default | Description |
|---|---|---|
| `default_backend` | `"memory"` | Backend used when a request omits `storage` |
| `max_memory_mb` | `128` | Budget for ciphertext plus a 256-byte-per-share overhead allowance |
| `max_shares` | `10000` | Maximum number of in-memory shares |
| `reject_when_full` | `true` | Must be `true`: CipherDrop never evicts live shares |
| `persistent_enabled` | `false` | Allow `storage: "persistent"` shares |
| `sqlite_path` | none | SQLite file for persistent shares and admin-created API tokens (created with mode `0600`) |
| `persistent_max_mb` | `1024` | Persistent ciphertext quota |
| `persistent_max_shares` | `100000` | Persistent share-count quota |
| `cleanup_interval_seconds` | `10` | Expiry reclamation interval (expiry is also enforced on every read) |

## `[shares]`

| Key | Default | Description |
|---|---|---|
| `max_size_bytes` | `1048576` | Maximum decoded ciphertext (including the 16-byte tag), 1 KiB to 64 MiB |
| `min_ttl_seconds` | `60` | Shortest allowed lifetime |
| `default_ttl_seconds` | `3600` | Lifetime when the request omits `ttl_seconds` |
| `max_ttl_seconds` | `604800` | Longest allowed lifetime (≤ 366 days) |
| `default_max_reads` | `1` | Reads when the request omits `max_reads` |
| `max_reads` | `100` | Maximum `max_reads` (≤ 1,000,000) |
| `allow_permanent` | `false` | Allow `ttl_seconds: null` for callers with `shares:create:persistent` |
| `allow_unlimited_reads` | `false` | Allow `max_reads: null` |

## `[auth]`

| Key | Default | Description |
|---|---|---|
| `anonymous_creation` | `false` | Allow share creation without a token |
| `anonymous_retrieval` | `true` | Allow consume/status without a token (capability-link model) |
| `tokens` | `[]` | Static API tokens (see below) |

```toml
[[auth.tokens]]
id = "4f1c2a9b7e30"            # 12 lowercase hex chars
name = "ci-pipeline"
sha256 = "9d4c…"               # hex SHA-256 of the full token string
scopes = ["shares:create"]
expires_at = "2027-01-01T00:00:00Z"   # optional
rate_limit_per_minute = 60            # optional
daily_create_quota = 500              # optional (counter resets daily and on restart)
```

Generate entries with `cipherdrop-server token generate --name NAME --scope SCOPE…`. Tokens created through `POST /api/v1/admin/tokens` are stored in SQLite when `sqlite_path` is set, otherwise in memory only (lost on restart).

## `[security]`

| Key | Default | Description |
|---|---|---|
| `require_https` | `true` | Requires an `https://` `public_url` and a way to guarantee HTTPS: native TLS, a trusted proxy, or a loopback listener. With a trusted proxy, requests whose `X-Forwarded-Proto` is not `https` are rejected. Enables HSTS |
| `request_timeout_seconds` | `15` | Whole-request timeout (1–300) |
| `trust_forwarded_headers` | `false` | Honour `X-Forwarded-For` / `X-Forwarded-Proto` from `trusted_proxies` only |
| `trusted_proxies` | `[]` | CIDRs of reverse proxies, e.g. `["127.0.0.1/32", "10.0.0.0/8"]` |
| `disable_core_dumps` | `true` | `RLIMIT_CORE=0`, plus `PR_SET_DUMPABLE=0` on Linux |
| `lock_memory` | `false` | `mlockall` all memory (needs `CAP_IPC_LOCK`; startup fails if it cannot) |

## `[rate_limit]`

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | |
| `create_per_minute` | `30` | Anonymous creations per IP |
| `read_per_minute` | `120` | Anonymous consume/status/revoke per IP |
| `token_default_per_minute` | `600` | Per-token rate unless set on the token |
| `ipv6_prefix_len` | `64` | IPv6 grouping prefix |
| `idempotency_ttl_seconds` | `600` | How long `Idempotency-Key` responses are replayable |
| `idempotency_max_entries` | `10000` | Bound on cached idempotency entries |

## `[cors]`

| Key | Default | Description |
|---|---|---|
| `allowed_origins` | `[]` | Exact origins allowed to call the API from browsers. Empty denies all cross-origin access. Wildcards are not supported |

## `[logging]`

| Key | Default | Description |
|---|---|---|
| `level` | `"warn"` | `error`, `warn`, `info`, `debug`, `trace`. `RUST_LOG` is deliberately ignored |
| `format` | `"json"` | `json` or `text` |

## `[metrics]`

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Serve `/metrics` |
| `require_token` | `true` | Require a token with `admin:metrics` |

## Example

See `config.example.toml` in the repository root.
