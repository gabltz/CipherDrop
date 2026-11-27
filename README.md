# CipherDrop

**Self-hosted, zero-knowledge secret sharing and pastebin.** Text is encrypted in the browser, CLI or SDK with AES-256-GCM. The server stores only ciphertext, in RAM by default, and destroys it after it is read or expires. The decryption key lives in the link's `#fragment`, which never reaches the server.

- 🔐 End-to-end encryption (AES-256-GCM, optional Argon2id password), with a documented and versioned wire format and cross-language test vectors
- 🔥 Atomic burn-after-reading: of 100 concurrent requests for a one-time share, at most one succeeds
- 🧠 RAM-only by default: bounded memory, no disk writes, nothing survives a restart; optional explicit SQLite persistence
- 🤖 API-first: versioned REST API, OpenAPI, RFC 9457 errors, scoped tokens, idempotency
- 🧰 SDKs for Rust, TypeScript/JavaScript and Python; a CLI; examples for PowerShell, C#, Bash and cURL
- 📦 One 12 MB container (static binary, `scratch`, non-root, read-only) with the web UI and documentation embedded
- 🛡️ Strict CSP, no trackers, no CDNs, no browser storage, sanitized logs

## Quick start (Docker)

```bash
# Local try-out over plain HTTP on localhost:
docker build -t cipherdrop .
docker run --rm -p 127.0.0.1:8080:8080 --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e CIPHERDROP__SERVER__PUBLIC_URL=http://localhost:8080 \
  -e CIPHERDROP__SECURITY__REQUIRE_HTTPS=false \
  -e CIPHERDROP__AUTH__ANONYMOUS_CREATION=true \
  cipherdrop
# → http://localhost:8080   (documentation at /docs)

# Production with automatic HTTPS (Caddy):
CIPHERDROP_DOMAIN=paste.example.com docker compose up -d --build
```

## Use it

```bash
printf '%s' "example secret" | cipherdrop --server https://paste.example.com create --ttl 1h --once
cipherdrop read < link.txt
```

```typescript
import { CipherDrop } from "@cipherdrop/sdk";
const client = new CipherDrop({ baseUrl: "https://paste.example.com", apiKey: process.env.CIPHERDROP_API_KEY });
const share = await client.createSecret("My secret", { ttl: 3600, maxReads: 1 });
console.log(share.url);
```

```python
from cipherdrop import CipherDrop
share = CipherDrop("https://paste.example.com").create_secret("My secret", ttl=3600, max_reads=1)
```

## Documentation

| | |
|---|---|
| [Overview](docs/index.md) | How it works, guarantees |
| [Quickstart](docs/quickstart.md) | Run and use |
| [API](docs/api.md) | Endpoints, auth, errors, rate limits |
| [Encryption protocol](docs/encryption.md) | Normative wire format, test vectors |
| [SDKs](docs/sdk.md) · [CLI](docs/cli.md) | Clients |
| [Security](docs/security.md) · [Threat model](THREAT_MODEL.md) | Guarantees and limitations |
| [Deployment](docs/deployment.md) · [Configuration](docs/configuration.md) | Operations |
| [Production runbook](deploy/production/README.md) | One-script install, automatic releases, rollback, operations |
| [Architecture](ARCHITECTURE.md) | Design decisions |

The same documentation is served by every instance at `/docs`, with an encrypting API playground and a bundled Swagger UI at `/docs/api/explorer`.

## Build from source

```bash
npm ci && npm run build           # frontend (embedded into the server) + TypeScript SDK
cargo build --release --locked    # cipherdrop-server, cipherdrop (CLI)
```

## Testing

```bash
cargo test --workspace                        # unit, integration, concurrency, property, vectors
npm test -w @cipherdrop/sdk                   # TS + plain JS SDK against vectors
python -m unittest discover -s sdk/python/tests
pwsh examples/powershell/Test-Vectors.ps1
cd tests/e2e && npx playwright install chromium && npx playwright test   # browser E2E
cargo bench -p cipherdrop-storage
```

Set `CIPHERDROP_TEST_SERVER=http://127.0.0.1:18080` to run the SDKs' live tests against a running instance.

## Status

CipherDrop 0.1.0 has **not been independently audited**. Read [SECURITY.md](SECURITY.md) and the [threat model](THREAT_MODEL.md) before deploying. Browser-based E2EE trusts the server to deliver honest JavaScript; prefer the CLI or SDKs where that matters.

## License

[MIT](LICENSE)
