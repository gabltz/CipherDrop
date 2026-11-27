# SDKs and integration examples

Every client encrypts locally and is interoperable with the web interface: a share created by any of them can be opened in the browser, and vice versa. All examples live in the repository's `examples/` directory and use synthetic data.

| Client | Location | Create | Read | Password | Tested against vectors |
|---|---|---|---|---|---|
| Rust SDK | `crates/sdk` | ✓ | ✓ | ✓ | ✓ |
| TypeScript SDK | `sdk/typescript` | ✓ | ✓ | ✓ | ✓ |
| JavaScript (same package, compiled ESM) | `sdk/typescript/dist` | ✓ | ✓ | ✓ | ✓ |
| Python SDK | `sdk/python` | ✓ | ✓ | ✓ | ✓ |
| CLI | `crates/cli` | ✓ | ✓ | ✓ | via Rust SDK |
| PowerShell 7 | `examples/powershell` | ✓ | ✓ | – | ✓ (password-less) |
| C# / .NET | `examples/dotnet` | ✓ | ✓ | – | ✓ (password-less) |
| Bash (via CLI) | `examples/bash` | ✓ | ✓ | ✓ | – |
| cURL | `examples/curl` | pre-encrypted | ciphertext only | – | – |

.NET has no built-in Argon2id, so the PowerShell and C# examples do not implement password-protected shares and refuse them explicitly. Use a vetted Argon2id library if you need passwords there.

## Rust

```toml
[dependencies]
cipherdrop-sdk = { git = "https://github.com/gabltz/CipherDrop", tag = "v0.1.0" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
secrecy = "0.10"
```

```rust
use cipherdrop_sdk::{Client, CreateOptions};
use secrecy::ExposeSecret;

#[tokio::main]
async fn main() -> Result<(), cipherdrop_sdk::Error> {
    let client = Client::builder("https://paste.example.com")
        .api_key(std::env::var("CIPHERDROP_API_KEY").ok())
        .build()?;

    let share = client
        .create_secret("My secret", CreateOptions { ttl_seconds: Some(3600), max_reads: Some(1), ..Default::default() })
        .await?;
    println!("{}", share.url.expose_secret());

    let payload = client.read(share.url.expose_secret(), None).await?;
    assert_eq!(payload.content, "My secret");
    Ok(())
}
```

The SDK uses rustls with the operating system's trust store. Certificate validation cannot be disabled; add a private CA with `add_root_certificate_pem`. `http://` base URLs are refused unless `allow_insecure_http(true)` is set for local development. Keys, links and revocation tokens are returned as `secrecy::SecretString` and redacted from `Debug` output. A full example is in `examples/rust`.

## TypeScript / JavaScript

One package serves both languages: it is written in TypeScript and published as ES modules with type declarations, so plain JavaScript consumers use exactly the same tested code. Works in modern browsers and Node.js ≥ 20.19 (Web Crypto plus a bundled Argon2id WebAssembly module, with no network fetches).

The package isn't on npm yet. Build it from a checkout:

```bash
git clone --depth 1 --branch v0.1.0 https://github.com/gabltz/CipherDrop && cd CipherDrop
npm ci && npm run build -w @cipherdrop/sdk
npm pack -w @cipherdrop/sdk          # -> cipherdrop-sdk-0.1.0.tgz; in your project: npm install /path/to/cipherdrop-sdk-0.1.0.tgz
```

Plain JavaScript (ESM):

```javascript
import { CipherDrop } from "@cipherdrop/sdk";
const client = new CipherDrop({ baseUrl: "https://paste.example.com" });
const share = await client.createSecret("My secret", { ttl: 3600, maxReads: 1 });
```

TypeScript:

```typescript
import { CipherDrop } from "@cipherdrop/sdk";

const client = new CipherDrop({
  baseUrl: "https://paste.example.com",
  apiKey: process.env.CIPHERDROP_API_KEY,
});

const share = await client.createSecret("My secret", { ttl: 3600, maxReads: 1 });
console.log(share.url);            // https://paste.example.com/s/…#v1.…

const secret = await client.read(share.url);         // consumes one retrieval
console.log(secret.content);

await client.revokeWithLink(share.revocationUrl);    // or client.revoke(id, token)
```

Options: `ttl` (seconds, `null` = never), `maxReads` (`null` = unlimited), `password`, `kdfCost`, `title`, `syntax`, `storage`, `idempotencyKey`. Errors are `ApiError` (`status`, `code`, `problem`) or `ProtocolError` (`code`: `decryption`, `password_required`, `malformed_url`, …).

## Python

The `cipherdrop` package (`sdk/python`) depends only on the well-established [`cryptography`](https://cryptography.io) package (AES-GCM, HKDF and Argon2id) plus the standard library. TLS certificates are always verified.

```bash
pip install "git+https://github.com/gabltz/CipherDrop@v0.1.0#subdirectory=sdk/python"   # or: pip install ./sdk/python
export CIPHERDROP_SERVER=https://paste.example.com
printf 'example secret' | python -m cipherdrop create --ttl 3600 --max-reads 1
python -m cipherdrop read < link.txt
```

```python
from cipherdrop import CipherDrop

client = CipherDrop("https://paste.example.com", api_key=None)
share = client.create_secret("My secret", ttl=3600, max_reads=1, password=None, title="optional")
print(share["url"])
print(client.read(share["url"])["content"])
client.revoke_with_link(share["revocation_url"])
```

All SDKs (Rust, TypeScript/JavaScript, Python) check the non-consuming status first when `read` is called without a password, so a password-protected share is never burned by a read that cannot decrypt it.

## PowerShell 7

```powershell
Import-Module ./examples/powershell/CipherDrop.psm1
$share = New-CipherDropSecret -Server https://paste.example.com -Secret (Read-Host -AsSecureString) -TtlSeconds 3600 -MaxReads 1
$share.Url
$text = Get-CipherDropSecret -Link $share.Url      # returns the decrypted content
```

Secrets are accepted as `SecureString`, and links are not written to the console history by the module.

## C# / .NET 8+

```bash
cd examples/dotnet
dotnet run -- create https://paste.example.com < secret.txt
dotnet run -- read < link.txt
```

Uses `System.Security.Cryptography.AesGcm` and `RandomNumberGenerator`.

## Bash

The official CLI is the recommended way to script CipherDrop in shell. See [CLI](cli.md) and `examples/bash/cipherdrop-demo.sh`.

```bash
link=$(printf '%s' "$DB_PASSWORD" | cipherdrop create --ttl 15m --once)
```

## Raw cURL

See [API reference § Raw cURL](api.md#raw-curl-with-a-pre-encrypted-payload). A plaintext cURL body is never end-to-end encrypted: always encrypt with a trusted local tool first.
