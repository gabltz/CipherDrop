# Benchmarks

- Storage engine (Criterion): `cargo bench -p cipherdrop-storage` (`crates/storage/benches/store.rs`).
- HTTP: run a release server with `rate_limit.enabled = false` and use any load generator (results below used Apache Bench).

## Measured results

Apple M-series laptop, macOS, Rust 1.99 release build, v0.1.0. Your hardware will differ; re-run before relying on these numbers.

| Benchmark | Result |
|---|---|
| `status` (in-memory lookup) | ~10 ns |
| `consume` (unlimited reads, Arc clone) | ~18 ns |
| insert + one-time consume, 1 KiB | ~355 ns |
| insert + one-time consume, 64 KiB | ~15.7 µs |
| reclaim 10k expired of 100k shares | ~12.5 ms |
| HTTP `POST /api/v1/shares` (1 KiB, 64 conns, ab) | ~29,900 req/s, 0 failures |
| HTTP `GET /status` (64 conns, ab) | ~27,900 req/s, 0 failures |
| Startup to healthy (incl. polling) | ~0.23 s |
| Idle RSS (macOS) / container memory (Linux, cgroup) | ~10 MB / ~1.9 MiB |
| RSS after 20k stored 1 KiB shares (macOS) | ~48 MB |
| Container image size | 12.3 MB |

Apache Bench is single-threaded and probably the bottleneck for the HTTP figures.
