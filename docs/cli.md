# CLI reference

`cipherdrop` is a statically linkable Rust client. It encrypts and decrypts locally and is the most trustworthy way to use CipherDrop, because its code does not come from the server at runtime.

```bash
cargo install --locked --git https://github.com/gabltz/CipherDrop cipherdrop-cli   # installs `cipherdrop`
cargo install --locked --path crates/cli                                          # from a checkout
```

Without Rust, use the copy in the release image:

```bash
alias cipherdrop='docker run --rm -i --entrypoint cipherdrop ghcr.io/gabltz/cipherdrop:latest'
```

## Design rules

- **Secrets never appear in arguments.** Content is read from stdin. Links and revocation links are read from stdin or a hidden TTY prompt. Passwords come from a hidden prompt (`--password`) or a file (`--password-file`). Arguments leak into shell history and `ps` output.
- **TLS is always verified** against the OS trust store. Add a private CA with `--ca-cert`; there is no option to disable verification. `http://` servers require `--allow-insecure-http`, which is meant for local development.
- **No automatic retries** of `read` (consume).
- **Links are only sent to their own server.** If a link's host differs from `--server`, the CLI refuses.

## Global options

| Option | Environment | Description |
|---|---|---|
| `--server URL` | `CIPHERDROP_SERVER` | Server base URL (for `read`/`status`/`revoke` the link's own URL is used) |
| `--api-key-file PATH` | `CIPHERDROP_API_KEY` (value) | API token |
| `--ca-cert PATH` | `CIPHERDROP_CA_CERT` | Extra trusted CA (PEM) |
| `--timeout SECS` | | Request timeout (default 30) |
| `--allow-insecure-http` | | Permit `http://` (local testing) |
| `--json` | | Machine-readable output |

## Commands

### `create`

```bash
printf '%s' "example secret" | cipherdrop create --ttl 1h --once
cat id_ed25519 | cipherdrop create --ttl 10m --once --password --title "deploy key"
kubectl get secret db -o json | cipherdrop --json create --max-reads 3 --syntax json
```

| Option | Description |
|---|---|
| `--ttl DURATION` | `10m`, `1h`, `7d`… (default: server default) |
| `--once` | Burn after the first read |
| `--max-reads N` | Allow N reads |
| `--unlimited-reads` | Unlimited until expiry (if the server allows it) |
| `--never-expire` | No expiry (requires `shares:create:persistent`) |
| `--persistent` | Store in the server's persistent backend (requires authorization) |
| `--password` / `--password-file PATH` | Additional password (never sent to the server) |
| `--title TEXT`, `--syntax LANG` | Encrypted metadata |
| `--idempotency-key KEY` | Safe retries of creation |

The share link is printed to **stdout**. Expiry, read limit and the revocation link are printed to **stderr**. With `--json`, stdout contains `{url, id, expires_at, max_reads, storage, revocation_url, revocation_token}`.

### `read`

```bash
cipherdrop read < link.txt
cipherdrop read --password            # prompts for link and password without echo
cipherdrop --json read < link.txt     # {"content":…, "title":…, "syntax":…}
```

### `status`

Non-consuming: `cipherdrop status < link.txt` (accepts a link or a bare share id).

### `revoke`

```bash
cipherdrop revoke < revocation-link.txt
CIPHERDROP_API_KEY=cdt_… cipherdrop revoke --id 3q2-7wUb1dEVxG3qkDfN8A   # requires shares:revoke
```

### `config`

Prints the server's public configuration.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error |
| 2 | Usage or configuration error (malformed link, empty input…) |
| 3 | Share unavailable (expired, consumed, revoked, unknown) |
| 4 | Authentication or authorization failure |
| 5 | Decryption failed (wrong key, wrong password, tampered data) |
| 6 | Rate limited, quota exceeded, capacity exhausted or overloaded |
| 7 | Network or TLS error |
