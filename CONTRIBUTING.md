# Contributing

Thanks for helping. Bug reports, documentation fixes and pull requests are all welcome.
For anything larger than a small fix, open an issue first so we can agree on the approach.
**Security problems go through [SECURITY.md](SECURITY.md), never public issues.**

## Development setup

1. Install Rust (see `rust-toolchain.toml`), Node.js ≥ 20.19 and Python ≥ 3.10.
2. `npm ci && npm run build`, then `cargo build`.
3. Before opening a pull request, run what CI runs:

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

## Pull requests

- Keep each pull request to one change, with tests, and update the documentation in `docs/`
  (it is also served by every instance at `/docs`) and `CHANGELOG.md` under *Unreleased*.
- CI must pass: lint, type checks, Rust, SDK and cross-language interop tests, browser
  end-to-end tests, the container smoke test and image scan, and `cargo audit`/`cargo deny`.
- Changes under `deploy/production/` reach production hosts automatically with the next
  release. Explain how you tested them.

## Releases

Maintainers release by bumping the version in `Cargo.toml` (`[workspace.package]`), updating
`CHANGELOG.md` and pushing a `vX.Y.Z` tag. See the
[production runbook](deploy/production/README.md#releasing).
