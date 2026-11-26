//! # CipherDrop protocol, version 1
//!
//! This crate is the single source of truth for CipherDrop interoperability:
//!
//! * [`api`]: JSON request/response types of the `/api/v1` REST API.
//! * [`envelope`]: the versioned encryption envelope and its strict validation.
//! * [`aad`]: canonical construction of AES-GCM associated data.
//! * [`payload`]: the plaintext document that is encrypted (content, title, syntax).
//! * [`url`]: share-URL and capability formats (`/s/{id}#v1.{key}`).
//! * [`crypto`] (feature `crypto`): client-side encryption and decryption.
//!
//! The normative specification lives in `docs/protocol.md`; deterministic
//! cross-language test vectors live in `testdata/vectors.json`.
//!
//! The server enables this crate with `default-features = false`: it uses
//! the wire types and validation, and does not link the content-decryption code.

#![forbid(unsafe_code)]

pub mod aad;
pub mod api;
pub mod encoding;
pub mod envelope;
pub mod payload;
pub mod url;

#[cfg(feature = "crypto")]
pub mod crypto;

pub use envelope::{
    Algorithm, DecodedEnvelope, DecodedKdf, EncryptedEnvelope, KdfAlgorithm, KdfParams,
};

/// Current (and only) protocol version.
pub const PROTOCOL_VERSION: u8 = 1;
/// Algorithm identifier used on the wire.
pub const ALGORITHM_AES_256_GCM: &str = "AES-256-GCM";
/// Content key length in bytes (AES-256).
pub const KEY_LEN: usize = 32;
/// AES-GCM nonce length in bytes (96 bits).
pub const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length in bytes (128 bits).
pub const TAG_LEN: usize = 16;
/// Share identifier length in bytes (128 bits of randomness).
pub const SHARE_ID_LEN: usize = 16;
/// Revocation token length in bytes (256 bits of randomness).
pub const REVOCATION_TOKEN_LEN: usize = 32;
/// Argon2id salt length in bytes.
pub const KDF_SALT_LEN: usize = 16;

/// Errors produced while parsing or validating protocol data.
///
/// Error messages never contain secret material or user content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("field `{0}` is not valid unpadded base64url")]
    Encoding(&'static str),
    #[error("field `{0}` has an invalid length")]
    Length(&'static str),
    #[error("key derivation parameters out of bounds: {0}")]
    KdfBounds(&'static str),
    #[error("malformed share URL or capability")]
    MalformedUrl,
    #[error("malformed plaintext payload")]
    MalformedPayload,
    #[error("decryption failed: wrong key, wrong password, or modified ciphertext")]
    Decryption,
    #[error("a password is required to decrypt this share")]
    PasswordRequired,
    #[error("this share is not password protected")]
    PasswordNotExpected,
    #[error("secure random number generator failure")]
    Rng,
    #[error("key derivation failed")]
    Kdf,
    #[error("payload too large")]
    TooLarge,
}
