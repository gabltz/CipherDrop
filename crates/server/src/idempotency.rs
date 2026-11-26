//! Bounded idempotency cache for `POST /api/v1/shares`.
//!
//! A client may send `Idempotency-Key: <1..=128 visible ASCII chars>`. A
//! repeated request with the same key, from the same principal and with a
//! byte-identical body, within the TTL returns the original response instead
//! of creating a second share. Reusing a key with a different body yields `422`.
//!
//! Entries are keyed by `SHA-256(principal ‖ key)` and store `SHA-256(body)`.
//! The cached response (which includes the revocation token) lives in RAM
//! only, for at most `idempotency_ttl_seconds`. When the cache is full, new
//! keys are not cached (the request still succeeds, without idempotency).

use std::collections::HashMap;

use cipherdrop_protocol::api::CreateShareResponse;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

#[derive(Debug)]
struct Entry {
    expires_at: u64,
    body_hash: [u8; 32],
    response: Option<CreateShareResponse>,
}

#[derive(Debug)]
pub struct IdempotencyCache {
    entries: Mutex<HashMap<[u8; 32], Entry>>,
    ttl: u64,
    max_entries: usize,
}

/// Outcome of claiming an idempotency key.
#[derive(Debug, PartialEq, Eq)]
pub enum Claim {
    /// First use: proceed and call [`IdempotencyCache::complete`] (or `abandon`).
    Proceed,
    /// Completed earlier with an identical body: replay this response.
    Replay(Box<CreateShareResponse>),
    /// Same key, different body.
    Conflict,
    /// A request with the same key is still in flight.
    InFlight,
    /// Cache full: proceed without idempotency.
    Uncached,
}

#[must_use]
pub fn valid_key(k: &str) -> bool {
    (1..=128).contains(&k.len()) && k.bytes().all(|b| b.is_ascii_graphic())
}

fn slot(principal: &str, key: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(principal.as_bytes());
    h.update([0u8]);
    h.update(key.as_bytes());
    h.finalize().into()
}

impl IdempotencyCache {
    #[must_use]
    pub fn new(ttl: u64, max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }

    pub fn claim(&self, principal: &str, key: &str, body: &[u8], now: u64) -> Claim {
        let s = slot(principal, key);
        let body_hash: [u8; 32] = Sha256::digest(body).into();
        let mut m = self.entries.lock();
        if let Some(e) = m.get(&s) {
            if e.expires_at > now {
                if e.body_hash != body_hash {
                    return Claim::Conflict;
                }
                return match &e.response {
                    Some(r) => Claim::Replay(Box::new(r.clone())),
                    None => Claim::InFlight,
                };
            }
            m.remove(&s);
        }
        if m.len() >= self.max_entries {
            m.retain(|_, e| e.expires_at > now);
            if m.len() >= self.max_entries {
                return Claim::Uncached;
            }
        }
        m.insert(
            s,
            Entry {
                expires_at: now.saturating_add(self.ttl),
                body_hash,
                response: None,
            },
        );
        Claim::Proceed
    }

    pub fn complete(&self, principal: &str, key: &str, response: &CreateShareResponse) {
        if let Some(e) = self.entries.lock().get_mut(&slot(principal, key)) {
            e.response = Some(response.clone());
        }
    }

    pub fn abandon(&self, principal: &str, key: &str) {
        self.entries.lock().remove(&slot(principal, key));
    }

    pub fn cleanup(&self, now: u64) {
        self.entries.lock().retain(|_, e| e.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherdrop_protocol::api::StorageBackend;

    fn resp() -> CreateShareResponse {
        CreateShareResponse {
            id: "i".into(),
            url: "u".into(),
            created_at: "c".into(),
            expires_at: None,
            max_reads: Some(1),
            storage: StorageBackend::Memory,
            revocation_token: "r".into(),
            revocation_url: "ru".into(),
        }
    }

    #[test]
    fn lifecycle() {
        let c = IdempotencyCache::new(10, 2);
        assert_eq!(c.claim("p", "k", b"body", 0), Claim::Proceed);
        assert_eq!(c.claim("p", "k", b"body", 1), Claim::InFlight);
        c.complete("p", "k", &resp());
        assert_eq!(
            c.claim("p", "k", b"body", 2),
            Claim::Replay(Box::new(resp()))
        );
        assert_eq!(c.claim("p", "k", b"other", 2), Claim::Conflict);
        assert_eq!(
            c.claim("q", "k", b"body", 2),
            Claim::Proceed,
            "scoped by principal"
        );
        assert_eq!(c.claim("r", "k", b"body", 2), Claim::Uncached, "bounded");
        assert_eq!(c.claim("p", "k", b"body", 11), Claim::Proceed, "expired");
        c.abandon("p", "k");
        assert_eq!(c.claim("p", "k", b"x", 11), Claim::Proceed);
    }

    #[test]
    fn key_validation() {
        assert!(valid_key("abc-123"));
        assert!(!valid_key(""));
        assert!(!valid_key("has space"));
        assert!(!valid_key(&"a".repeat(129)));
    }
}
