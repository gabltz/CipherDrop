# Contributing

1. Install Rust (see `rust-toolchain.toml`), Node.js ≥ 20.19 and Python ≥ 3.10.
2. `npm ci && npm run build`, then `cargo build`.
3. Before opening a pull request:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
npm run lint && npm run check && npm test
python -m unittest discover -s sdk/python/tests
(cd tests/e2e && npx playwright test)
```

## Rules

- **Protocol changes** must update `crates/protocol`, `docs/encryption.md`, the test vectors (`cargo run -p cipherdrop-protocol --example generate_vectors`), and every SDK. Wire-incompatible changes require a new protocol version.
- Never log request bodies, URIs, identifiers, tokens or IP addresses.
- No new runtime network dependencies (CDNs, fonts, telemetry) in the web interface.
- No browser storage APIs in the frontend (enforced by ESLint).
- Use only synthetic secrets in tests, fixtures and examples.
- Do not implement cryptographic primitives; use established libraries.
- Document significant design decisions in `ARCHITECTURE.md`.
