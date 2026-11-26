//! Storage engine benchmarks: insert, consume, status, expiry reclamation.
//!
//! Run with `cargo bench -p cipherdrop-storage`.

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

use cipherdrop_protocol::url::ShareId;
use cipherdrop_storage::memory::{MemoryLimits, MemoryStore};
use cipherdrop_storage::{NewShare, ShareMeta, StoredEnvelope, Verifier};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};

static CTR: AtomicU64 = AtomicU64::new(1);

fn next_id() -> ShareId {
    // Spread ids across shards like random ids would.
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&n.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
    b[8..].copy_from_slice(&n.to_le_bytes());
    ShareId::from_bytes(b)
}

fn share(len: usize, exp: Option<u64>, reads: Option<u32>) -> NewShare {
    NewShare {
        envelope: StoredEnvelope {
            nonce: [0; 12],
            ciphertext: vec![0xAB; len],
            kdf: None,
        },
        meta: ShareMeta {
            created_at: 0,
            expires_at: exp,
            remaining_reads: reads,
        },
        revocation: Verifier([0; 32]),
    }
}

fn big_store() -> MemoryStore {
    MemoryStore::new(MemoryLimits {
        max_bytes: usize::MAX,
        max_shares: usize::MAX,
    })
}

fn benches(c: &mut Criterion) {
    for len in [1024usize, 64 * 1024] {
        let mut g = c.benchmark_group(format!("memory/{len}B"));
        g.throughput(Throughput::Elements(1));
        let store = big_store();
        g.bench_function("insert", |b| {
            b.iter_batched(
                || (next_id(), share(len, Some(u64::MAX), Some(1))),
                |(id, s)| store.insert(id, s, 0).unwrap(),
                BatchSize::SmallInput,
            );
        });
        let store = big_store();
        g.bench_function("insert+consume_once", |b| {
            b.iter_batched(
                || (next_id(), share(len, Some(u64::MAX), Some(1))),
                |(id, s)| {
                    store.insert(id, s, 0).unwrap();
                    black_box(store.consume(&id, 0).unwrap());
                },
                BatchSize::SmallInput,
            );
        });
        let store = big_store();
        let id = next_id();
        store.insert(id, share(len, None, None), 0).unwrap();
        g.bench_function("consume_unlimited", |b| {
            b.iter(|| black_box(store.consume(&id, 0).unwrap()))
        });
        g.bench_function("status", |b| b.iter(|| black_box(store.status(&id, 0))));
        g.finish();
    }

    let mut g = c.benchmark_group("memory/expiry");
    g.sample_size(20);
    g.bench_function("purge_10k_of_100k", |b| {
        b.iter_batched(
            || {
                let store = big_store();
                for i in 0..100_000u64 {
                    let exp = if i % 10 == 0 { 10 } else { 1_000 };
                    store
                        .insert(next_id(), share(64, Some(exp), Some(1)), 0)
                        .unwrap();
                }
                store
            },
            |store| assert_eq!(store.purge_expired(10), 10_000),
            BatchSize::PerIteration,
        );
    });
    g.finish();
}

criterion_group!(store_benches, benches);
criterion_main!(store_benches);
