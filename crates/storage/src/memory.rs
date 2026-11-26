//! Bounded, sharded, RAM-only share store.
//!
//! ## Design
//!
//! * **Sharding.** Shares live in `SHARDS` independent `parking_lot::Mutex<HashMap>`
//!   maps, selected by the first byte of the (uniformly random) share id. Every
//!   operation on a share takes exactly one shard lock, which makes
//!   check-and-decrement linearizable without a global lock.
//! * **Atomic consumption.** [`MemoryStore::consume`] validates expiry,
//!   decrements the read counter and (on the last read) removes the entry
//!   inside one critical section. With 100 concurrent consumers of a one-time
//!   share, exactly one observes the ciphertext.
//! * **Admission control.** A small global accounting mutex tracks the share
//!   count and accounted bytes. Inserts that would exceed either budget are
//!   rejected; nothing is ever evicted to make room.
//! * **Expiry.** A min-heap of `(expires_at, id)` with lazy deletion lets
//!   the cleaner pop only expired candidates (O(k log n)) instead of scanning.
//!   Stale heap entries (consumed/revoked shares) are compacted when the heap
//!   grows past twice the live population. Expiry is also checked on every read.
//! * **Lock order.** `heap → shard` is the only nested order. No code path
//!   acquires the heap lock while holding a shard lock.
//!
//! The store has no persistence hooks of any kind.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;

use cipherdrop_protocol::url::ShareId;
use parking_lot::Mutex;

use crate::{
    AccessCheck, Consumed, NewShare, RevokeAuth, ShareMeta, Status, StoreError, StoredEnvelope,
    Verifier,
};

const SHARDS: usize = 64;

/// Fixed per-entry accounting overhead in bytes, covering the entry struct,
/// the `Arc` header, the hash-map slot (with load-factor slack), the expiry-heap
/// entry and allocator rounding. Deliberately conservative.
pub const ENTRY_OVERHEAD_BYTES: usize = 256;

/// Accounted cost of storing an envelope.
#[must_use]
pub fn entry_cost(env: &StoredEnvelope) -> usize {
    // Vec capacity, not length: what the allocator actually handed out.
    env.ciphertext.capacity() + ENTRY_OVERHEAD_BYTES
}

/// Capacity limits for the memory store.
#[derive(Debug, Clone, Copy)]
pub struct MemoryLimits {
    /// Budget for accounted bytes (ciphertext + per-entry overhead).
    pub max_bytes: usize,
    pub max_shares: usize,
}

struct Entry {
    envelope: Arc<StoredEnvelope>,
    meta: ShareMeta,
    revocation: Verifier,
    access: Option<Verifier>,
    access_failures: u32,
    cost: usize,
}

#[derive(Default)]
struct Accounting {
    shares: usize,
    bytes: usize,
}

/// Snapshot of store usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub shares: usize,
    pub bytes: usize,
    pub heap_entries: usize,
}

/// The RAM-only store. Cheap to share via `Arc`.
pub struct MemoryStore {
    shards: Box<[Mutex<HashMap<ShareId, Entry>>]>,
    accounting: Mutex<Accounting>,
    expiry: Mutex<BinaryHeap<Reverse<(u64, ShareId)>>>,
    limits: MemoryLimits,
}

impl core::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemoryStore")
            .field("limits", &self.limits)
            .field("usage", &self.usage())
            .finish()
    }
}

impl MemoryStore {
    #[must_use]
    pub fn new(limits: MemoryLimits) -> Self {
        let shards = (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect();
        Self {
            shards,
            accounting: Mutex::new(Accounting::default()),
            expiry: Mutex::new(BinaryHeap::new()),
            limits,
        }
    }

    #[must_use]
    pub const fn limits(&self) -> MemoryLimits {
        self.limits
    }

    fn shard(&self, id: &ShareId) -> &Mutex<HashMap<ShareId, Entry>> {
        &self.shards[usize::from(id.as_bytes()[0]) % SHARDS]
    }

    fn try_reserve(&self, cost: usize) -> Result<(), StoreError> {
        let mut a = self.accounting.lock();
        if a.shares >= self.limits.max_shares
            || a.bytes.saturating_add(cost) > self.limits.max_bytes
        {
            return Err(StoreError::CapacityExhausted);
        }
        a.shares += 1;
        a.bytes += cost;
        Ok(())
    }

    fn release(&self, cost: usize) {
        let mut a = self.accounting.lock();
        a.shares = a.shares.saturating_sub(1);
        a.bytes = a.bytes.saturating_sub(cost);
    }

    /// Insert a new share. Rejects (never evicts) when the store is full.
    ///
    /// When the store is full, expired entries are reclaimed synchronously
    /// once before giving up.
    ///
    /// # Errors
    /// [`StoreError::CapacityExhausted`] or [`StoreError::Duplicate`].
    pub fn insert(&self, id: ShareId, share: NewShare, now: u64) -> Result<(), StoreError> {
        let cost = entry_cost(&share.envelope);
        if self.try_reserve(cost).is_err() {
            self.purge_expired(now);
            self.try_reserve(cost)?;
        }
        let expires_at = share.meta.expires_at;
        {
            let mut shard = self.shard(&id).lock();
            if shard.contains_key(&id) {
                drop(shard);
                self.release(cost);
                return Err(StoreError::Duplicate);
            }
            shard.insert(
                id,
                Entry {
                    envelope: Arc::new(share.envelope),
                    meta: share.meta,
                    revocation: share.revocation,
                    access: share.access,
                    access_failures: 0,
                    cost,
                },
            );
        }
        if let Some(exp) = expires_at {
            self.expiry.lock().push(Reverse((exp, id)));
        }
        Ok(())
    }

    /// Atomically validate and consume one retrieval.
    ///
    /// # Errors
    /// [`StoreError::Unavailable`] if the share is unknown, expired, exhausted or revoked.
    pub fn consume(
        &self,
        id: &ShareId,
        now: u64,
        access: AccessCheck<'_>,
    ) -> Result<Consumed, StoreError> {
        let mut shard = self.shard(id).lock();
        let entry = shard.get_mut(id).ok_or(StoreError::Unavailable)?;
        if entry.meta.expires_at.is_some_and(|e| e <= now) {
            let removed = shard.remove(id);
            drop(shard);
            if let Some(e) = removed {
                self.release(e.cost);
            }
            return Err(StoreError::Unavailable);
        }
        // Server-enforced password gate, checked in the same critical section.
        if let Some(v) = entry.access {
            let ok = access.key.is_some_and(|k| v.verify(k));
            if !ok {
                entry.access_failures = entry.access_failures.saturating_add(1);
                if access.max_failures > 0 && entry.access_failures >= access.max_failures {
                    let removed = shard.remove(id);
                    drop(shard);
                    if let Some(e) = removed {
                        self.release(e.cost);
                    }
                    return Err(StoreError::AccessDenied { destroyed: true });
                }
                return Err(StoreError::AccessDenied { destroyed: false });
            }
        }
        match entry.meta.remaining_reads {
            None => Ok(Consumed {
                envelope: Arc::clone(&entry.envelope),
                remaining_reads: None,
                expires_at: entry.meta.expires_at,
            }),
            Some(n) if n > 1 => {
                entry.meta.remaining_reads = Some(n - 1);
                Ok(Consumed {
                    envelope: Arc::clone(&entry.envelope),
                    remaining_reads: Some(n - 1),
                    expires_at: entry.meta.expires_at,
                })
            }
            Some(_) => {
                // Final permitted read (n == 1; n == 0 is never stored): remove
                // while still holding the shard lock.
                let e = shard.remove(id).ok_or(StoreError::Unavailable)?;
                drop(shard);
                self.release(e.cost);
                Ok(Consumed {
                    envelope: e.envelope,
                    remaining_reads: Some(0),
                    expires_at: e.meta.expires_at,
                })
            }
        }
    }

    /// Non-consuming status lookup.
    #[must_use]
    pub fn status(&self, id: &ShareId, now: u64) -> Option<Status> {
        let shard = self.shard(id).lock();
        let e = shard.get(id)?;
        if e.meta.expires_at.is_some_and(|x| x <= now) {
            return None;
        }
        Some(Status {
            expires_at: e.meta.expires_at,
            remaining_reads: e.meta.remaining_reads,
            password_protected: e.envelope.kdf.is_some(),
            access_protected: e.access.is_some(),
            kdf: e.envelope.kdf,
        })
    }

    /// Revoke (delete) a share.
    ///
    /// # Errors
    /// [`StoreError::Unavailable`] if absent/expired, [`StoreError::Forbidden`]
    /// if the revocation token does not match.
    pub fn revoke(&self, id: &ShareId, auth: RevokeAuth<'_>, now: u64) -> Result<(), StoreError> {
        let mut shard = self.shard(id).lock();
        let e = shard.get(id).ok_or(StoreError::Unavailable)?;
        let expired = e.meta.expires_at.is_some_and(|x| x <= now);
        if !expired && !auth.allows(&e.revocation) {
            return Err(StoreError::Forbidden);
        }
        let e = shard.remove(id).ok_or(StoreError::Unavailable)?;
        drop(shard);
        self.release(e.cost);
        if expired {
            Err(StoreError::Unavailable)
        } else {
            Ok(())
        }
    }

    /// Remove every share whose expiry is `<= now`. Returns the number removed.
    pub fn purge_expired(&self, now: u64) -> usize {
        let due: Vec<(u64, ShareId)> = {
            let mut heap = self.expiry.lock();
            let mut due = Vec::new();
            while let Some(Reverse((exp, _))) = heap.peek() {
                if *exp > now {
                    break;
                }
                if let Some(Reverse(item)) = heap.pop() {
                    due.push(item);
                }
            }
            due
        };
        let mut removed = 0;
        for (exp, id) in due {
            let mut shard = self.shard(&id).lock();
            // Only remove if the live entry is the one this heap item refers to.
            let matches = shard
                .get(&id)
                .is_some_and(|e| e.meta.expires_at == Some(exp));
            if matches && let Some(e) = shard.remove(&id) {
                drop(shard);
                self.release(e.cost);
                removed += 1;
            }
        }
        self.maybe_compact();
        removed
    }

    /// Rebuild the expiry heap when stale entries dominate, bounding its size
    /// to O(live shares).
    fn maybe_compact(&self) {
        let live = self.accounting.lock().shares;
        let mut heap = self.expiry.lock();
        if heap.len() <= 2 * live + 1024 {
            return;
        }
        let mut fresh = Vec::with_capacity(live);
        for shard in &*self.shards {
            let shard = shard.lock();
            fresh.extend(
                shard
                    .iter()
                    .filter_map(|(id, e)| e.meta.expires_at.map(|x| Reverse((x, *id)))),
            );
        }
        *heap = BinaryHeap::from(fresh);
    }

    #[must_use]
    pub fn usage(&self) -> Usage {
        let a = self.accounting.lock();
        let (shares, bytes) = (a.shares, a.bytes);
        drop(a);
        Usage {
            shares,
            bytes,
            heap_entries: self.expiry.lock().len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    fn id(n: u16) -> ShareId {
        let mut b = [0u8; 16];
        b[..2].copy_from_slice(&n.to_be_bytes());
        b[15] = 0xaa;
        ShareId::from_bytes(b)
    }

    fn share(len: usize, expires_at: Option<u64>, reads: Option<u32>) -> NewShare {
        NewShare {
            envelope: StoredEnvelope {
                nonce: [0; 12],
                ciphertext: vec![7; len],
                kdf: None,
            },
            meta: ShareMeta {
                created_at: 0,
                expires_at,
                remaining_reads: reads,
            },
            revocation: Verifier::from_secret(b"revocation-secret"),
            access: None,
        }
    }

    fn store() -> MemoryStore {
        MemoryStore::new(MemoryLimits {
            max_bytes: 1 << 20,
            max_shares: 100,
        })
    }

    #[test]
    fn one_time_share_is_consumed_exactly_once() {
        let s = store();
        s.insert(id(1), share(32, Some(100), Some(1)), 0).unwrap();
        let c = s.consume(&id(1), 1, AccessCheck::none()).unwrap();
        assert_eq!(c.remaining_reads, Some(0));
        assert_eq!(c.envelope.ciphertext.len(), 32);
        assert_eq!(
            s.consume(&id(1), 1, AccessCheck::none()).unwrap_err(),
            StoreError::Unavailable
        );
        assert_eq!(s.usage().shares, 0);
        assert_eq!(s.usage().bytes, 0);
    }

    #[test]
    fn limited_reads_count_down() {
        let s = store();
        s.insert(id(1), share(8, None, Some(3)), 0).unwrap();
        assert_eq!(
            s.consume(&id(1), 0, AccessCheck::none())
                .unwrap()
                .remaining_reads,
            Some(2)
        );
        assert_eq!(s.status(&id(1), 0).unwrap().remaining_reads, Some(2));
        assert_eq!(
            s.consume(&id(1), 0, AccessCheck::none())
                .unwrap()
                .remaining_reads,
            Some(1)
        );
        assert_eq!(
            s.consume(&id(1), 0, AccessCheck::none())
                .unwrap()
                .remaining_reads,
            Some(0)
        );
        assert!(s.consume(&id(1), 0, AccessCheck::none()).is_err());
        assert!(s.status(&id(1), 0).is_none());
    }

    #[test]
    fn unlimited_reads() {
        let s = store();
        s.insert(id(1), share(8, Some(10), None), 0).unwrap();
        for _ in 0..50 {
            assert_eq!(
                s.consume(&id(1), 5, AccessCheck::none())
                    .unwrap()
                    .remaining_reads,
                None
            );
        }
    }

    #[test]
    fn expired_shares_are_unavailable_and_reclaimed() {
        let s = store();
        s.insert(id(1), share(8, Some(10), Some(5)), 0).unwrap();
        s.insert(id(2), share(8, Some(20), Some(5)), 0).unwrap();
        assert!(s.status(&id(1), 9).is_some());
        assert!(s.status(&id(1), 10).is_none());
        assert_eq!(
            s.consume(&id(1), 10, AccessCheck::none()).unwrap_err(),
            StoreError::Unavailable
        );
        assert_eq!(s.usage().shares, 1, "expired entry removed on access");
        assert_eq!(s.purge_expired(19), 0);
        assert_eq!(s.purge_expired(20), 1);
        assert_eq!(s.usage(), Usage::default());
        // Never resurrected.
        assert!(s.consume(&id(2), 0, AccessCheck::none()).is_err());
    }

    #[test]
    fn revocation_requires_matching_token() {
        let s = store();
        s.insert(id(1), share(8, Some(100), Some(5)), 0).unwrap();
        assert_eq!(
            s.revoke(&id(1), RevokeAuth::Token(b"wrong"), 1),
            Err(StoreError::Forbidden)
        );
        assert!(s.status(&id(1), 1).is_some());
        s.revoke(&id(1), RevokeAuth::Token(b"revocation-secret"), 1)
            .unwrap();
        assert!(s.consume(&id(1), 1, AccessCheck::none()).is_err());
        assert_eq!(
            s.revoke(&id(1), RevokeAuth::Admin, 1),
            Err(StoreError::Unavailable)
        );
        assert_eq!(s.usage().shares, 0);
    }

    #[test]
    fn capacity_is_enforced_without_eviction() {
        let s = MemoryStore::new(MemoryLimits {
            max_bytes: 10 * (100 + ENTRY_OVERHEAD_BYTES),
            max_shares: 1000,
        });
        for i in 0..10 {
            s.insert(id(i), share(100, Some(1000), Some(1)), 0).unwrap();
        }
        assert_eq!(
            s.insert(id(99), share(100, Some(1000), Some(1)), 0),
            Err(StoreError::CapacityExhausted)
        );
        // Existing shares are intact.
        for i in 0..10 {
            assert!(s.status(&id(i), 0).is_some());
        }
        // Freed capacity is reusable.
        s.consume(&id(0), 0, AccessCheck::none()).unwrap();
        s.insert(id(99), share(100, Some(1000), Some(1)), 0)
            .unwrap();
    }

    #[test]
    fn share_count_limit_and_expiry_reclaim_on_full() {
        let s = MemoryStore::new(MemoryLimits {
            max_bytes: 1 << 20,
            max_shares: 2,
        });
        s.insert(id(1), share(1, Some(5), Some(1)), 0).unwrap();
        s.insert(id(2), share(1, Some(500), Some(1)), 0).unwrap();
        assert_eq!(
            s.insert(id(3), share(1, None, Some(1)), 1),
            Err(StoreError::CapacityExhausted)
        );
        // Once id(1) has expired, a full store reclaims it synchronously.
        s.insert(id(3), share(1, None, Some(1)), 5).unwrap();
        assert!(s.status(&id(1), 0).is_none());
    }

    #[test]
    fn heap_is_compacted() {
        let s = MemoryStore::new(MemoryLimits {
            max_bytes: usize::MAX,
            max_shares: usize::MAX,
        });
        for i in 0..5000u16 {
            s.insert(id(i), share(1, Some(1_000_000), Some(1)), 0)
                .unwrap();
            s.consume(&id(i), 0, AccessCheck::none()).unwrap();
        }
        assert_eq!(s.usage().heap_entries, 5000);
        s.purge_expired(1);
        assert!(s.usage().heap_entries <= 1024);
    }

    #[test]
    fn access_gate_blocks_and_destroys_after_failures() {
        let s = store();
        let mut sh = share(8, None, Some(2));
        sh.access = Some(Verifier::from_secret(b"access-key"));
        s.insert(id(1), sh, 0).unwrap();
        let wrong = AccessCheck {
            key: Some(b"nope"),
            max_failures: 3,
        };
        let none = AccessCheck {
            key: None,
            max_failures: 3,
        };
        let right = AccessCheck {
            key: Some(b"access-key"),
            max_failures: 3,
        };
        assert_eq!(
            s.consume(&id(1), 0, none).unwrap_err(),
            StoreError::AccessDenied { destroyed: false }
        );
        assert_eq!(
            s.consume(&id(1), 0, wrong).unwrap_err(),
            StoreError::AccessDenied { destroyed: false }
        );
        assert_eq!(
            s.status(&id(1), 0).unwrap().remaining_reads,
            Some(2),
            "failures never consume"
        );
        assert!(s.status(&id(1), 0).unwrap().access_protected);
        assert_eq!(
            s.consume(&id(1), 0, right).unwrap().remaining_reads,
            Some(1)
        );
        assert_eq!(
            s.consume(&id(1), 0, wrong).unwrap_err(),
            StoreError::AccessDenied { destroyed: true }
        );
        assert!(s.status(&id(1), 0).is_none());
        assert_eq!(s.usage().shares, 0);
    }

    #[test]
    fn hundred_concurrent_consumers_one_winner() {
        for round in 0..20u16 {
            let s = Arc::new(store());
            s.insert(id(round), share(64, Some(100), Some(1)), 0)
                .unwrap();
            let barrier = Arc::new(Barrier::new(100));
            let handles: Vec<_> = (0..100)
                .map(|_| {
                    let s = Arc::clone(&s);
                    let b = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        b.wait();
                        s.consume(&id(round), 1, AccessCheck::none()).is_ok()
                    })
                })
                .collect();
            let wins = handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|w| *w)
                .count();
            assert_eq!(wins, 1);
        }
    }

    #[test]
    fn concurrent_limited_reads_never_exceed_limit() {
        let s = Arc::new(store());
        s.insert(id(7), share(64, None, Some(10)), 0).unwrap();
        let barrier = Arc::new(Barrier::new(64));
        let handles: Vec<_> = (0..64)
            .map(|_| {
                let s = Arc::clone(&s);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    s.consume(&id(7), 0, AccessCheck::none())
                        .ok()
                        .map(|c| c.remaining_reads)
                })
            })
            .collect();
        let mut remaining: Vec<u32> = handles
            .into_iter()
            .filter_map(|h| h.join().unwrap())
            .map(|r| r.unwrap())
            .collect();
        remaining.sort_unstable();
        assert_eq!(
            remaining,
            (0..10).collect::<Vec<_>>(),
            "each count observed exactly once"
        );
    }

    #[test]
    fn concurrent_revoke_and_consume_are_linearizable() {
        for round in 0..50u16 {
            let s = Arc::new(store());
            s.insert(id(round), share(8, None, Some(1)), 0).unwrap();
            let b = Arc::new(Barrier::new(2));
            let (s1, b1) = (Arc::clone(&s), Arc::clone(&b));
            let t1 = std::thread::spawn(move || {
                b1.wait();
                s1.consume(&id(round), 0, AccessCheck::none()).is_ok()
            });
            let (s2, b2) = (Arc::clone(&s), Arc::clone(&b));
            let t2 = std::thread::spawn(move || {
                b2.wait();
                s2.revoke(&id(round), RevokeAuth::Admin, 0).is_ok()
            });
            let (consumed, revoked) = (t1.join().unwrap(), t2.join().unwrap());
            // Exactly one operation wins; never both, never neither.
            assert!(consumed ^ revoked, "consumed={consumed} revoked={revoked}");
            assert_eq!(s.usage().shares, 0);
        }
    }
}
