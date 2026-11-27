# CipherDrop

[![CI](https://github.com/gabltz/CipherDrop/actions/workflows/ci.yml/badge.svg)](https://github.com/gabltz/CipherDrop/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/gabltz/CipherDrop?sort=semver)](https://github.com/gabltz/CipherDrop/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Self-hosted, zero-knowledge secret sharing and pastebin.** Text is encrypted on your device (browser, CLI or SDK) with AES-256-GCM before it is sent. The server stores only ciphertext, in RAM by default, and destroys it after it has been read or has expired. The key travels in the link's `#fragment`, which browsers never send to the server.

```text
https://paste.example.com/s/3q2-7wUb1dEVxG3qkDfN8A#v1.mTq9x…
                           └──── share id ──────┘ └─ key: stays on the client
```

## Features

- **End-to-end encrypted.** AES-256-GCM, optional Argon2id password enforced by the server without it ever learning the password. A versioned, documented wire format with cross-language test vectors.
- **Burn after reading, atomically.** Of 100 concurrent requests for a one-time share, exactly one gets the ciphertext. Link previews and scanners never consume a share.
- **RAM-only by default.** Bounded memory, no disk writes, nothing survives a restart. SQLite persistence is optional and explicit.
- **API-first.** Versioned REST API, OpenAPI document, RFC 9457 errors, scoped API tokens, idempotency keys and rate limits.
- **Clients for everything.** SDKs for Rust, TypeScript/JavaScript and Python, a CLI, and examples for PowerShell, C#, Bash and cURL, all interoperable with the web UI.
- **Small and locked down.** One 12 MB multi-arch image (static binary, `scratch`, non-root, read-only) with the web UI and documentation built in. Strict CSP, no trackers, no CDNs, no browser storage, no sensitive data in logs.
- **Production-ready deployment.** One install script. The host then deploys each signed release itself, with health and smoke checks and automatic rollback.

## Try it

```bash
docker run --rm -p 127.0.0.1:8080:8080 --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e CIPHERDROP__SERVER__PUBLIC_URL=http://localhost:8080 \
  -e CIPHERDROP__SECURITY__REQUIRE_HTTPS=false \
  -e CIPHERDROP__AUTH__ANONYMOUS_CREATION=true \
  ghcr.io/gabltz/cipherdrop:latest
```

Open <http://localhost:8080>. The documentation is served at `/docs` and an API explorer at `/docs/api/explorer`. Plain HTTP is only acceptable on `localhost`. Deployments must use HTTPS.

## Run it in production

On a Debian or Ubuntu server, run one script ([runbook](deploy/production/README.md)):

```bash
curl -fsSLO https://raw.githubusercontent.com/gabltz/CipherDrop/main/deploy/production/install.sh
sudo bash install.sh --domain paste.example.com
```

It asks how the site is reached:

| Mode | Use when |
|---|---|
| `local` | a reverse proxy (nginx, Caddy, Apache, Traefik…) on the same server terminates TLS |
| `remote` | a reverse proxy on **another** server forwards to this one (`proxy_pass`); the port is firewalled to the proxy |
| `caddy` | there is no reverse proxy: the bundled Caddy serves HTTPS with automatic certificates |

The server then installs every new release by itself. It verifies the release's Sigstore signature against this repository's release workflow, checks the new version, and rolls back if anything fails. Ready-made configurations for nginx, Caddy, Apache, Traefik and plain Docker Compose are in [`deploy/`](deploy/) and [docs/deployment.md](docs/deployment.md).

## Use it

**Web:** paste text, pick an expiry, keep *Burn after reading* on, and share the link.

**CLI.** It encrypts locally, and its code doesn't come from the server:

```bash
cargo install --locked --git https://github.com/gabltz/CipherDrop cipherdrop-cli
# or run it from the image:  alias cipherdrop='docker run --rm -i --entrypoint cipherdrop ghcr.io/gabltz/cipherdrop:latest'

printf '%s' "example secret" | cipherdrop --server https://paste.example.com create --ttl 1h --once
pbpaste | cipherdrop read          # the link is read from stdin, never from arguments
```

**TypeScript / JavaScript:**

```typescript
import { CipherDrop } from "@cipherdrop/sdk";

const client = new CipherDrop({ baseUrl: "https://paste.example.com", apiKey: process.env.CIPHERDROP_API_KEY });
const share = await client.createSecret("example secret", { ttl: 3600, maxReads: 1 });
console.log(share.url);
```

**Python:**

```python
from cipherdrop import CipherDrop

share = CipherDrop("https://paste.example.com", api_key="cdt_…").create_secret("example secret", ttl=3600, max_reads=1)
print(share.url)
```

The SDKs aren't on npm or PyPI yet. [docs/sdk.md](docs/sdk.md) shows how to install them from this repository.

## Documentation

| | |
|---|---|
| [Overview](docs/index.md) | How it works, what the server can and cannot see |
| [Quickstart](docs/quickstart.md) | Run it, create a share, enable API tokens |
| [API](docs/api.md) | Endpoints, authentication, errors, rate limits |
| [Encryption protocol](docs/encryption.md) | Normative wire format and test vectors |
| [SDKs](docs/sdk.md) · [CLI](docs/cli.md) | Clients and integration examples |
| [Security](docs/security.md) · [Threat model](THREAT_MODEL.md) · [Security review](SECURITY_AUDIT.md) | Guarantees, limitations, findings |
| [Deployment](docs/deployment.md) · [Configuration](docs/configuration.md) | Self-hosting reference |
| [Production runbook](deploy/production/README.md) | One-script install, automatic releases, rollback, operations |
| [Architecture](ARCHITECTURE.md) | Design decisions |

## Security

The server never has the keys. It only ever stores ciphertext and the minimum metadata it needs to enforce expiry and read limits. Two limits to keep in mind:

- **Browser encryption trusts the server.** The browser runs JavaScript that the server delivers, so a malicious or compromised server could serve code that leaks keys. Use the CLI or an SDK when that matters.
- **No independent audit yet.** CipherDrop has been through an internal security review ([SECURITY_AUDIT.md](SECURITY_AUDIT.md)); every finding is fixed or documented as accepted. It has not been independently audited.

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Development

```bash
npm ci && npm run build            # web UI (embedded into the server) and TypeScript SDK
cargo build --release --locked     # cipherdrop-server and the cipherdrop CLI
cargo test --workspace --locked    # unit, integration, concurrency, property and vector tests
```

[CONTRIBUTING.md](CONTRIBUTING.md) lists the full test suite and the project rules. Releases are cut by pushing a `vX.Y.Z` tag (see the [runbook](deploy/production/README.md#releasing)).

## License

[MIT](LICENSE)
