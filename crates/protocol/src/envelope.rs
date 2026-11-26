//! The versioned encryption envelope.
//!
//! An envelope is everything a recipient needs, besides the share key (and
//! optional password), to decrypt a share. It contains no secret material:
//! the nonce, ciphertext (with appended 16-byte GCM tag) and the public
//! Argon2id parameters when a password is used.

use serde::{Deserialize, Serialize};

use crate::encoding::{b64_decode, b64_decode_array, b64_encode, decoded_len_upper};
use crate::{KDF_SALT_LEN, NONCE_LEN, PROTOCOL_VERSION, ProtocolError, TAG_LEN};

/// Content-encryption algorithm. Only AES-256-GCM is defined for protocol v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum Algorithm {
    #[serde(rename = "AES-256-GCM")]
    Aes256Gcm,
}

impl Algorithm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => crate::ALGORITHM_AES_256_GCM,
        }
    }
}

/// Password key-derivation function. Only Argon2id (v0x13) is defined for protocol v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum KdfAlgorithm {
    #[serde(rename = "argon2id")]
    Argon2id,
}

/// Inclusive bounds for Argon2id parameters accepted by every v1 implementation.
///
/// Lower bounds prevent trivially weak password protection; upper bounds
/// prevent a malicious sender from making recipients' devices allocate
/// unbounded memory or spin for minutes.
pub mod kdf_bounds {
    /// Minimum memory cost in KiB (19 MiB, OWASP minimum for Argon2id).
    pub const MIN_MEMORY_KIB: u32 = 19_456;
    /// Maximum memory cost in KiB (256 MiB).
    pub const MAX_MEMORY_KIB: u32 = 262_144;
    pub const MIN_ITERATIONS: u32 = 2;
    pub const MAX_ITERATIONS: u32 = 10;
    pub const MIN_PARALLELISM: u32 = 1;
    pub const MAX_PARALLELISM: u32 = 4;
    /// Recommended defaults: 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT_MEMORY_KIB: u32 = 65_536;
    pub const DEFAULT_ITERATIONS: u32 = 3;
    pub const DEFAULT_PARALLELISM: u32 = 1;
}

/// Public Argon2id parameters for password-protected shares (wire form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct KdfParams {
    /// Always `argon2id`.
    pub algorithm: KdfAlgorithm,
    /// 16-byte random salt, unpadded base64url (22 characters).
    #[cfg_attr(feature = "openapi", schema(example = "AAECAwQFBgcICQoLDA0ODw"))]
    pub salt: String,
    /// Memory cost in KiB (19456..=262144).
    #[cfg_attr(feature = "openapi", schema(example = 65536))]
    pub memory_kib: u32,
    /// Number of passes (2..=10).
    #[cfg_attr(feature = "openapi", schema(example = 3))]
    pub iterations: u32,
    /// Degree of parallelism (1..=4).
    #[cfg_attr(feature = "openapi", schema(example = 1))]
    pub parallelism: u32,
}

/// Decoded and validated Argon2id parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedKdf {
    pub salt: [u8; KDF_SALT_LEN],
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl DecodedKdf {
    /// Validate parameter bounds.
    ///
    /// # Errors
    /// Returns [`ProtocolError::KdfBounds`] when a parameter is outside [`kdf_bounds`].
    pub fn check_bounds(&self) -> Result<(), ProtocolError> {
        use kdf_bounds::*;
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib) {
            return Err(ProtocolError::KdfBounds("memory_kib"));
        }
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations) {
            return Err(ProtocolError::KdfBounds("iterations"));
        }
        if !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&self.parallelism) {
            return Err(ProtocolError::KdfBounds("parallelism"));
        }
        Ok(())
    }

    #[must_use]
    pub fn to_wire(&self) -> KdfParams {
        KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            salt: b64_encode(&self.salt),
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        }
    }
}

impl KdfParams {
    /// Decode and validate.
    ///
    /// # Errors
    /// Returns an error for malformed salts or out-of-bounds parameters.
    pub fn decode(&self) -> Result<DecodedKdf, ProtocolError> {
        let d = DecodedKdf {
            salt: b64_decode_array::<KDF_SALT_LEN>(&self.salt, "kdf.salt")?,
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        };
        d.check_bounds()?;
        Ok(d)
    }
}

/// The encryption envelope in its JSON wire form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EncryptedEnvelope {
    /// Protocol version; must be `1`.
    #[cfg_attr(feature = "openapi", schema(example = 1))]
    pub version: u8,
    /// Must be `AES-256-GCM`.
    pub algorithm: Algorithm,
    /// 12-byte GCM nonce, unpadded base64url (16 characters).
    #[cfg_attr(feature = "openapi", schema(example = "AAECAwQFBgcICQoL"))]
    pub nonce: String,
    /// GCM ciphertext followed by the 16-byte authentication tag, unpadded base64url.
    pub ciphertext: String,
    /// Present only for password-protected shares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<KdfParams>,
}

/// A validated envelope with binary fields decoded.
#[derive(Clone, PartialEq, Eq)]
pub struct DecodedEnvelope {
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with the 16-byte tag appended.
    pub ciphertext: Vec<u8>,
    pub kdf: Option<DecodedKdf>,
}

impl core::fmt::Debug for DecodedEnvelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print ciphertext, even though it is not secret on its own.
        f.debug_struct("DecodedEnvelope")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("password_protected", &self.kdf.is_some())
            .finish_non_exhaustive()
    }
}

impl EncryptedEnvelope {
    /// Strictly validate and decode the envelope.
    ///
    /// `max_ciphertext_len` bounds the decoded ciphertext length (including tag)
    /// and is checked *before* decoding to avoid large allocations.
    ///
    /// # Errors
    /// Returns a [`ProtocolError`] describing the first violated rule.
    pub fn decode(&self, max_ciphertext_len: usize) -> Result<DecodedEnvelope, ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        // `algorithm` is an enum; serde has already rejected unknown values.
        let nonce = b64_decode_array::<NONCE_LEN>(&self.nonce, "nonce")?;
        if decoded_len_upper(self.ciphertext.len()) > max_ciphertext_len {
            return Err(ProtocolError::TooLarge);
        }
        let ciphertext = b64_decode(&self.ciphertext, "ciphertext")?;
        if ciphertext.len() < TAG_LEN {
            return Err(ProtocolError::Length("ciphertext"));
        }
        if ciphertext.len() > max_ciphertext_len {
            return Err(ProtocolError::TooLarge);
        }
        let kdf = self.kdf.as_ref().map(KdfParams::decode).transpose()?;
        Ok(DecodedEnvelope {
            nonce,
            ciphertext,
            kdf,
        })
    }
}

impl DecodedEnvelope {
    /// Re-encode into the wire form.
    #[must_use]
    pub fn to_wire(&self) -> EncryptedEnvelope {
        EncryptedEnvelope {
            version: PROTOCOL_VERSION,
            algorithm: Algorithm::Aes256Gcm,
            nonce: b64_encode(&self.nonce),
            ciphertext: b64_encode(&self.ciphertext),
            kdf: self.kdf.as_ref().map(DecodedKdf::to_wire),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EncryptedEnvelope {
        EncryptedEnvelope {
            version: 1,
            algorithm: Algorithm::Aes256Gcm,
            nonce: b64_encode(&[7u8; 12]),
            ciphertext: b64_encode(&[9u8; 40]),
            kdf: None,
        }
    }

    #[test]
    fn valid_envelope_decodes() {
        let d = sample().decode(1024).unwrap();
        assert_eq!(d.nonce, [7u8; 12]);
        assert_eq!(d.ciphertext.len(), 40);
        assert_eq!(d.to_wire(), sample());
    }

    #[test]
    fn rejects_bad_version_and_lengths() {
        let mut e = sample();
        e.version = 2;
        assert_eq!(e.decode(1024), Err(ProtocolError::UnsupportedVersion));
        let mut e = sample();
        e.nonce = b64_encode(&[0u8; 16]);
        assert!(e.decode(1024).is_err());
        let mut e = sample();
        e.ciphertext = b64_encode(&[0u8; 15]);
        assert_eq!(e.decode(1024), Err(ProtocolError::Length("ciphertext")));
        assert_eq!(sample().decode(39), Err(ProtocolError::TooLarge));
    }

    #[test]
    fn rejects_unknown_fields_and_algorithms() {
        let j = r#"{"version":1,"algorithm":"AES-256-GCM","nonce":"x","ciphertext":"y","extra":1}"#;
        assert!(serde_json::from_str::<EncryptedEnvelope>(j).is_err());
        let j = r#"{"version":1,"algorithm":"AES-128-GCM","nonce":"x","ciphertext":"y"}"#;
        assert!(serde_json::from_str::<EncryptedEnvelope>(j).is_err());
    }

    #[test]
    fn kdf_bounds_enforced() {
        let mut e = sample();
        e.kdf = Some(KdfParams {
            algorithm: KdfAlgorithm::Argon2id,
            salt: b64_encode(&[1u8; 16]),
            memory_kib: kdf_bounds::MAX_MEMORY_KIB + 1,
            iterations: 3,
            parallelism: 1,
        });
        assert_eq!(e.decode(1024), Err(ProtocolError::KdfBounds("memory_kib")));
        e.kdf.as_mut().unwrap().memory_kib = 65_536;
        e.kdf.as_mut().unwrap().iterations = 1;
        assert_eq!(e.decode(1024), Err(ProtocolError::KdfBounds("iterations")));
        e.kdf.as_mut().unwrap().iterations = 3;
        e.kdf.as_mut().unwrap().parallelism = 0;
        assert_eq!(e.decode(1024), Err(ProtocolError::KdfBounds("parallelism")));
        e.kdf.as_mut().unwrap().parallelism = 1;
        assert!(e.decode(1024).unwrap().kdf.is_some());
    }
}
