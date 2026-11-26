# Quickstart

## Run with Docker

The image contains a single static binary with the web interface embedded. In the default ephemeral mode it needs no volume, and its root filesystem can be read-only.

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e CIPHERDROP__SERVER__PUBLIC_URL=http://localhost:8080 \
  -e CIPHERDROP__SECURITY__REQUIRE_HTTPS=false \
  -e CIPHERDROP__AUTH__ANONYMOUS_CREATION=true \
  cipherdrop:latest
```

Open <http://localhost:8080>. `require_https=false` is only acceptable for local testing: browsers expose the Web Crypto API on `localhost`, but production deployments must use HTTPS (see [Deployment](deployment.md)).

For a production-style setup behind a reverse proxy, use [`compose.yml`](deployment.md#docker-compose).

## Run the binary

```bash
cargo build --release -p cipherdrop-server        # after building the frontend, see below
./target/release/cipherdrop-server --config config.toml
./target/release/cipherdrop-server check-config --config config.toml
```

Building from source:

```bash
npm ci                    # installs frontend + TypeScript SDK dependencies
npm run build             # builds frontend/dist (embedded into the server binary)
cargo build --release     # builds cipherdrop-server and the cipherdrop CLI
```

## Create a share

**Web:** paste text, choose an expiry, keep *Burn after reading* on, and click **Create secure link**.

**CLI:**

```bash
export CIPHERDROP_SERVER=https://paste.example.com
printf '%s' "example secret" | cipherdrop create --ttl 1h --once
# https://paste.example.com/s/3q2-7wUb1dEVxG3qkDfN8A#v1.mTq...  (the key is after #v1.)
```

Retrieve it (the link is read from stdin, never from arguments):

```bash
pbpaste | cipherdrop read      # or: cipherdrop read  (prompts without echo)
```

**TypeScript:**

```typescript
import { CipherDrop } from "@cipherdrop/sdk";

const client = new CipherDrop({ baseUrl: "https://paste.example.com", apiKey: process.env.CIPHERDROP_API_KEY });
const share = await client.createSecret("My secret", { ttl: 3600, maxReads: 1 });
console.log(share.url);
```

## Enable authentication

Anonymous creation is **disabled by default**. Generate a token and add the printed snippet to your configuration:

```bash
cipherdrop-server token generate --name ci --scope shares:create
```

```text
# Token (shown once; store it in your secret manager):
# cdt_4f1c2a9b7e30_Hq3...

[[auth.tokens]]
id = "4f1c2a9b7e30"
name = "ci"
sha256 = "9d4c..."
scopes = ["shares:create"]
```

Only the SHA-256 verifier is stored in the configuration. Clients send `Authorization: Bearer cdt_...`. To allow anyone to create shares (a public pastebin), set `auth.anonymous_creation = true`.
