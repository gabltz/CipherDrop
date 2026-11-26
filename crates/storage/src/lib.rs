//! CipherDrop storage engines.
//!
//! * [`memory::MemoryStore`]: the default, RAM-only, bounded, sharded store.
//!   It never touches the filesystem.
//! * [`sqlite::PersistentStore`] (feature `sqlite`): an optional, separate
//!   SQLite store used **only** for shares explicitly created with
//!   `storage = "persistent"`, plus administrative API tokens.
//!
//! The two engines share no code path for writing share data: the memory
//! store has no persistence hooks, and the server routes a share to SQLite
//! only after an explicit, authorized request. Neither store sees plaintext
//! or keys; both store only the opaque encryption envelope and the minimal
//! operational metadata listed in [`ShareMeta`].

#![forbid(unsafe_code)]

pub mod memory;
#[cfg(feature = "sqlite")]
pub mod sqlite;

use std::sync::Arc;

use cipherdrop_protocol::NONCE_LEN;
use cipherdrop_protocol::envelope::DecodedKdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Opaque encrypted envelope as stored. The ciphertext buffer is wiped on drop
/// (best effort; it is already encrypted, this only limits residue).
#[derive(Clone, PartialEq, Eq)]
pub struct StoredEnvelope {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub kdf: Option<DecodedKdf>,
}

impl Drop for StoredEnvelope {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
    }
}

impl core::fmt::Debug for StoredEnvelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoredEnvelope")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// Operational metadata the server needs for lookup, expiry, authorization
/// and accounting. Contains no user content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareMeta {
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds; `None` = never expires.
    pub expires_at: Option<u64>,
    /// `None` = unlimited.
    pub remaining_reads: Option<u32>,
}

/// SHA-256 verifier of a high-entropy revocation token.
///
/// A fast hash is appropriate here because the token carries 256 bits of
/// entropy; a slow password hash would add nothing but CPU cost.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Verifier(pub [u8; 32]);

impl Verifier {
    #[must_use]
    pub fn from_secret(secret: &[u8]) -> Self {
        Self(Sha256::digest(secret).into())
    }

    /// Constant-time comparison against a presented secret.
    #[must_use]
    pub fn verify(&self, presented_secret: &[u8]) -> bool {
        let h: [u8; 32] = Sha256::digest(presented_secret).into();
        bool::from(self.0.ct_eq(&h))
    }
}

impl core::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Verifier(<redacted>)")
    }
}

/// A new share to insert.
#[derive(Debug)]
pub struct NewShare {
    pub envelope: StoredEnvelope,
    pub meta: ShareMeta,
    pub revocation: Verifier,
    /// Server-enforced password gate: `SHA-256(access_key)`.
    pub access: Option<Verifier>,
}

/// Access-key policy applied atomically during consumption.
#[derive(Debug, Clone, Copy)]
pub struct AccessCheck<'a> {
    /// Access key presented by the client (raw 32 bytes), if any.
    pub key: Option<&'a [u8]>,
    /// Wrong attempts after which the share is destroyed (`0` = never destroy).
    pub max_failures: u32,
}

impl AccessCheck<'_> {
    /// No access key presented, default failure limit.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            key: None,
            max_failures: 10,
        }
    }
}

/// Result of a successful consume.
#[derive(Debug, Clone)]
pub struct Consumed {
    pub envelope: Arc<StoredEnvelope>,
    /// Remaining reads *after* this retrieval (`Some(0)` = deleted).
    pub remaining_reads: Option<u32>,
    pub expires_at: Option<u64>,
}

/// Non-consuming status information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub expires_at: Option<u64>,
    pub remaining_reads: Option<u32>,
    pub password_protected: bool,
    pub access_protected: bool,
    pub kdf: Option<DecodedKdf>,
}

/// Storage errors. Messages contain no identifiers or content.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    /// The share does not exist, has expired, was consumed or was revoked.
    #[error("share unavailable")]
    Unavailable,
    /// The presented revocation token does not match.
    #[error("revocation token mismatch")]
    Forbidden,
    /// Inserting would exceed the configured share-count or memory budget.
    #[error("storage capacity exhausted")]
    CapacityExhausted,
    /// The payload is larger than the configured maximum.
    #[error("payload too large")]
    TooLarge,
    /// An identifier collision (astronomically unlikely with 128-bit ids).
    #[error("duplicate identifier")]
    Duplicate,
    /// Missing or wrong access key. `destroyed` is true when this attempt
    /// exhausted the failure budget and the share was deleted.
    #[error("access denied")]
    AccessDenied { destroyed: bool },
    /// Backend failure (persistent store only).
    #[error("storage backend error")]
    Backend,
}

/// How a revocation request is authorized.
#[derive(Debug, Clone, Copy)]
pub enum RevokeAuth<'a> {
    /// Anonymous revocation capability presented by the creator.
    Token(&'a [u8]),
    /// A caller holding the `shares:revoke` scope.
    Admin,
}

impl RevokeAuth<'_> {
    fn allows(&self, v: &Verifier) -> bool {
        match self {
            Self::Token(t) => v.verify(t),
            Self::Admin => true,
        }
    }
}
