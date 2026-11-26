# CipherDrop documentation

CipherDrop is a self-hosted, zero-knowledge secret sharing service and pastebin. Text is encrypted on the client (browser, CLI, SDK) with AES-256-GCM. The server stores only ciphertext, in RAM by default, and deletes it after the configured number of retrievals or when it expires.

## How it works

```text
 Sender (browser / CLI / SDK)                     CipherDrop server                    Recipient
 ─────────────────────────────                    ─────────────────                    ─────────
 1. key K = 32 random bytes
 2. ciphertext = AES-256-GCM(K, payload)
 3. POST /api/v1/shares {nonce, ciphertext} ───▶  stores ciphertext in RAM
                                           ◀───   {id, url, revocation_token}
 4. link = url + "#v1." + base64url(K)
 5. send link ─────────────────────────────────────────────────────────────────────▶  6. opens /s/{id}#v1.K
                                                                                     (fragment stays local)
                                                  GET /status (does not consume) ◀── 7. page shows "Reveal"
                                                  POST /consume: atomically      ◀── 8. user clicks Reveal
                                                  decrements / deletes ─────────▶
                                                                                     9. decrypt locally with K
```

The part of the link after `#` is a URL *fragment*. Browsers never send fragments to servers, so the key is never transmitted to CipherDrop.

## What the server knows

| The server never receives | The server does see |
|---|---|
| Plaintext content, titles, syntax hints | Ciphertext and its length (padded to 256-byte buckets by official clients) |
| Share keys (URL fragment) | Share id, creation and expiry time, remaining retrievals |
| Optional passwords | Whether a share is password protected, and the public Argon2id parameters |
| Decrypted data of any kind | Client IP addresses (for rate limiting; never logged) |

The server cannot verify that an API caller actually encrypted its payload. It treats every upload as opaque, untrusted bytes.

## Guarantees and non-guarantees

- **Atomic burn-after-reading.** Validation and consumption of the final permitted retrieval happen in one critical section. With 100 concurrent requests for a one-time share, exactly one receives the ciphertext.
- **RAM-only by default.** Ephemeral shares are never written to disk by CipherDrop, and they are lost on restart, which is intentional. The operating system can still swap memory to disk; see [Deployment](deployment.md#keeping-secrets-out-of-persistent-storage).
- **Link scanners do not burn secrets.** Opening a share page, `HEAD` requests and link previews never consume a share. Only an explicit `POST /consume` does. Automated clients that actively call that endpoint cannot be distinguished from humans.
- **No retrieval confirmation.** "Consumed" means the server released the ciphertext, not that a human read it. A network failure after consumption can lose a one-time secret.
- **Browser-delivered code is trusted code.** A malicious or compromised server can serve modified JavaScript that leaks keys. Independently distributed clients (CLI, SDKs) do not have this weakness. See [Security](security.md).

## Where to go next

- [Quickstart](quickstart.md): run CipherDrop and create your first share.
- [API reference](api.md): endpoints, authentication, errors, rate limits, and an interactive playground.
- [Encryption protocol](encryption.md): the normative wire format and cross-language test vectors.
- [SDKs and examples](sdk.md): Rust, TypeScript, Python, PowerShell, C#, Bash and raw cURL.
- [CLI](cli.md): the `cipherdrop` command-line client.
- [Security and threat model](security.md)
- [Deployment](deployment.md): Docker, systemd, reverse proxies and memory hygiene.
- [Configuration reference](configuration.md)
