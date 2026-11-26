//! Model-based property test: the memory store must behave exactly like a
//! simple reference model under arbitrary operation sequences, and its
//! accounting must never drift or underflow.

use std::collections::HashMap;

use cipherdrop_protocol::url::ShareId;
use cipherdrop_storage::memory::{ENTRY_OVERHEAD_BYTES, MemoryLimits, MemoryStore};
use cipherdrop_storage::{NewShare, RevokeAuth, ShareMeta, StoreError, StoredEnvelope, Verifier};
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Op {
    Insert {
        id: u8,
        len: u16,
        ttl: Option<u8>,
        reads: Option<u8>,
    },
    Consume {
        id: u8,
    },
    Status {
        id: u8,
    },
    Revoke {
        id: u8,
        good_token: bool,
    },
    Advance {
        secs: u8,
    },
    Purge,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (
            0u8..16,
            0u16..512,
            proptest::option::of(1u8..20),
            proptest::option::of(1u8..5)
        )
            .prop_map(|(id, len, ttl, reads)| Op::Insert {
                id,
                len,
                ttl,
                reads
            }),
        (0u8..16).prop_map(|id| Op::Consume { id }),
        (0u8..16).prop_map(|id| Op::Status { id }),
        (0u8..16, any::<bool>()).prop_map(|(id, good_token)| Op::Revoke { id, good_token }),
        (0u8..10).prop_map(|secs| Op::Advance { secs }),
        Just(Op::Purge),
    ]
}

#[derive(Debug, Clone)]
struct ModelEntry {
    expires_at: Option<u64>,
    remaining: Option<u32>,
    cost: usize,
}

fn sid(n: u8) -> ShareId {
    let mut b = [0u8; 16];
    b[0] = n.wrapping_mul(37);
    b[1] = n;
    ShareId::from_bytes(b)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn memory_store_matches_model(ops in proptest::collection::vec(op(), 1..200)) {
        let limits = MemoryLimits { max_bytes: 6 * (512 + ENTRY_OVERHEAD_BYTES), max_shares: 8 };
        let store = MemoryStore::new(limits);
        let mut model: HashMap<u8, ModelEntry> = HashMap::new();
        let mut now: u64 = 1000;

        let live = |m: &HashMap<u8, ModelEntry>, id: u8, now: u64| {
            m.get(&id).is_some_and(|e| e.expires_at.is_none_or(|x| x > now))
        };

        for op in ops {
            match op {
                Op::Insert { id, len, ttl, reads } => {
                    let ciphertext = vec![0u8; usize::from(len) + 16];
                    let cost = ciphertext.capacity() + ENTRY_OVERHEAD_BYTES;
                    let share = NewShare {
                        envelope: StoredEnvelope { nonce: [0; 12], ciphertext, kdf: None },
                        meta: ShareMeta {
                            created_at: now,
                            expires_at: ttl.map(|t| now + u64::from(t)),
                            remaining_reads: reads.map(u32::from),
                        },
                        revocation: Verifier::from_secret(b"good"),
                    };
                    let r = store.insert(sid(id), share, now);
                    // Model: an insert reclaims expired entries when full.
                    let used = |m: &HashMap<u8, ModelEntry>| (m.len(), m.values().map(|e| e.cost).sum::<usize>());
                    let fits = |m: &HashMap<u8, ModelEntry>| {
                        let (n, b) = used(m);
                        n < limits.max_shares && b + cost <= limits.max_bytes
                    };
                    // Store semantics: when full, reclaim expired entries once;
                    // then capacity is checked before duplicates.
                    if !fits(&model) {
                        model.retain(|_, e| e.expires_at.is_none_or(|x| x > now));
                    }
                    if !fits(&model) {
                        prop_assert_eq!(r, Err(StoreError::CapacityExhausted));
                    } else if let std::collections::hash_map::Entry::Vacant(slot) = model.entry(id) {
                        prop_assert_eq!(r, Ok(()));
                        slot.insert(ModelEntry {
                            expires_at: ttl.map(|t| now + u64::from(t)),
                            remaining: reads.map(u32::from),
                            cost,
                        });
                    } else {
                        prop_assert_eq!(r, Err(StoreError::Duplicate));
                    }
                }
                Op::Consume { id } => {
                    let r = store.consume(&sid(id), now);
                    if live(&model, id, now) {
                        let e = model.get_mut(&id).unwrap();
                        let c = r.expect("live share must be consumable");
                        match e.remaining {
                            None => prop_assert_eq!(c.remaining_reads, None),
                            Some(n) => {
                                prop_assert_eq!(c.remaining_reads, Some(n - 1));
                                if n == 1 { model.remove(&id); } else { e.remaining = Some(n - 1); }
                            }
                        }
                    } else {
                        prop_assert_eq!(r.unwrap_err(), StoreError::Unavailable);
                        model.remove(&id);
                    }
                }
                Op::Status { id } => {
                    let s = store.status(&sid(id), now);
                    prop_assert_eq!(s.is_some(), live(&model, id, now));
                    if let Some(s) = s {
                        prop_assert_eq!(s.remaining_reads, model[&id].remaining);
                    }
                }
                Op::Revoke { id, good_token } => {
                    let auth = if good_token { RevokeAuth::Token(b"good") } else { RevokeAuth::Token(b"bad") };
                    let r = store.revoke(&sid(id), auth, now);
                    if live(&model, id, now) {
                        if good_token {
                            prop_assert_eq!(r, Ok(()));
                            model.remove(&id);
                        } else {
                            prop_assert_eq!(r, Err(StoreError::Forbidden));
                        }
                    } else {
                        prop_assert_eq!(r, Err(StoreError::Unavailable));
                        model.remove(&id);
                    }
                }
                Op::Advance { secs } => now += u64::from(secs),
                Op::Purge => {
                    store.purge_expired(now);
                    model.retain(|_, e| e.expires_at.is_none_or(|x| x > now));
                }
            }
            // Accounting invariant: store usage equals the model exactly.
            let u = store.usage();
            prop_assert_eq!(u.shares, model.len());
            prop_assert_eq!(u.bytes, model.values().map(|e| e.cost).sum::<usize>());
            prop_assert!(u.shares <= limits.max_shares);
            prop_assert!(u.bytes <= limits.max_bytes);
        }
    }
}
