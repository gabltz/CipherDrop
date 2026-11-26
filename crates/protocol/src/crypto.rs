//! Client-side encryption for protocol v1.
//!
//! ## Construction
//!
//! * `K`: 32-byte share key from the OS CSPRNG, carried only in the URL fragment.
//! * Without password, the content-encryption key is `CEK = K`.
//! * With password `P`:
//!   ```text
//!   PW  = UTF-8(NFC(P))
//!   PWK = Argon2id(v=0x13, m, t, p, salt, PW) → 32 bytes
//!   CEK = HKDF-SHA256(salt = salt, IKM = K ‖ PWK, info = "cipherdrop/v1/cek/password") → 32 bytes
//!   ```
//!   The password *supplements* the random key: an attacker needs both the
//!   link and the password, and offline guessing of the password is only
//!   possible for someone who already holds the full link and the ciphertext.
//! * `nonce`: 12 fresh random bytes per encryption (keys are single-use, so
//!   a key/nonce pair is never reused).
//! * `ciphertext = AES-256-GCM(CEK, nonce, plaintext, AAD)` with the 16-byte tag appended.
//! * `AAD` = [`crate::aad::build_aad`].
//!
//! All secret intermediates are held in [`zeroize::Zeroizing`] buffers and
//! wiped on drop (best effort: copies made by the allocator, the OS or the
//! compiler cannot be ruled out).

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use argon2::{Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::aad::build_aad;
use crate::encoding::{b64_decode_array, b64_encode};
use crate::envelope::{DecodedEnvelope, DecodedKdf, kdf_bounds};
use crate::payload::SecretPayload;
use crate::{KDF_SALT_LEN, KEY_LEN, NONCE_LEN, ProtocolError};

/// HKDF `info` string for password-protected content keys.
pub const HKDF_INFO_PASSWORD: &[u8] = b"cipherdrop/v1/cek/password";
/// HKDF `info` string for the access key of password-protected shares.
pub const HKDF_INFO_ACCESS: &[u8] = b"cipherdrop/v1/access";

/// Default padding granularity for plaintext payloads (bytes).
pub const DEFAULT_PAD_TO: usize = 256;

/// Fill `buf` from the operating system CSPRNG.
///
/// # Errors
/// Returns [`ProtocolError::Rng`] if the OS RNG is unavailable.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), ProtocolError> {
    getrandom::fill(buf).map_err(|_| ProtocolError::Rng)
}

/// A 256-bit share key. Wiped from memory on drop; `Debug` is redacted.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ShareKey([u8; KEY_LEN]);

impl core::fmt::Debug for ShareKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ShareKey(<redacted>)")
    }
}

impl ShareKey {
    /// Generate a fresh random key.
    ///
    /// # Errors
    /// Returns [`ProtocolError::Rng`] if the OS RNG fails.
    pub fn generate() -> Result<Self, ProtocolError> {
        let mut k = [0u8; KEY_LEN];
        random_bytes(&mut k)?;
        let key = Self(k);
        k.zeroize();
        Ok(key)
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Parse the 43-character base64url form used in URL fragments.
    ///
    /// # Errors
    /// Returns an error if the text is not exactly 32 bytes of canonical base64url.
    pub fn from_b64(s: &str) -> Result<Self, ProtocolError> {
        let mut b = b64_decode_array::<KEY_LEN>(s, "key")?;
        let key = Self(b);
        b.zeroize();
        Ok(key)
    }

    /// The 43-character base64url form, in a zeroizing buffer.
    #[must_use]
    pub fn to_b64(&self) -> Zeroizing<String> {
        Zeroizing::new(b64_encode(&self.0))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Argon2id cost parameters chosen by the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCost {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfCost {
    fn default() -> Self {
        Self {
            memory_kib: kdf_bounds::DEFAULT_MEMORY_KIB,
            iterations: kdf_bounds::DEFAULT_ITERATIONS,
            parallelism: kdf_bounds::DEFAULT_PARALLELISM,
        }
    }
}

/// Normalize a password (Unicode NFC) and return its UTF-8 bytes.
fn normalize_password(password: &str) -> Zeroizing<Vec<u8>> {
    let s: Zeroizing<String> = Zeroizing::new(password.nfc().collect());
    Zeroizing::new(s.as_bytes().to_vec())
}

/// Keys derived from the share key and a password (one Argon2id evaluation).
pub struct PasswordKeys {
    /// Content-encryption key.
    pub cek: Zeroizing<[u8; KEY_LEN]>,
    /// Access key presented to the server on consume (never used for encryption).
    pub access_key: Zeroizing<[u8; KEY_LEN]>,
}

impl core::fmt::Debug for PasswordKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PasswordKeys(<redacted>)")
    }
}

/// Derive the content key and the access key from `K` and a password.
///
/// ```text
/// PRK        = HKDF-Extract(salt, K ‖ Argon2id(NFC(pw), salt, m, t, p))
/// CEK        = HKDF-Expand(PRK, "cipherdrop/v1/cek/password", 32)
/// access_key = HKDF-Expand(PRK, "cipherdrop/v1/access", 32)
/// ```
///
/// The two outputs are independent: knowing `access_key` (which the server
/// sees on consume) reveals nothing about `CEK`, and neither can be computed
/// without the 256-bit share key `K`.
///
/// # Errors
/// Fails for empty passwords or out-of-bounds KDF parameters.
pub fn derive_password_keys(
    key: &ShareKey,
    k: &DecodedKdf,
    password: &str,
) -> Result<PasswordKeys, ProtocolError> {
    k.check_bounds()?;
    if password.is_empty() {
        return Err(ProtocolError::PasswordRequired);
    }
    let pw = normalize_password(password);
    let params = Params::new(k.memory_kib, k.iterations, k.parallelism, Some(KEY_LEN))
        .map_err(|_| ProtocolError::Kdf)?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let mut pwk = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(&pw, &k.salt, pwk.as_mut())
        .map_err(|_| ProtocolError::Kdf)?;
    let mut ikm = Zeroizing::new([0u8; 2 * KEY_LEN]);
    ikm[..KEY_LEN].copy_from_slice(key.as_bytes());
    ikm[KEY_LEN..].copy_from_slice(pwk.as_ref());
    let hk = Hkdf::<Sha256>::new(Some(&k.salt), ikm.as_ref());
    let mut cek = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(HKDF_INFO_PASSWORD, cek.as_mut())
        .map_err(|_| ProtocolError::Kdf)?;
    let mut access_key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(HKDF_INFO_ACCESS, access_key.as_mut())
        .map_err(|_| ProtocolError::Kdf)?;
    Ok(PasswordKeys { cek, access_key })
}

/// Server-side verifier for an access key: `SHA-256(access_key)`.
#[must_use]
pub fn access_verifier(access_key: &[u8; KEY_LEN]) -> [u8; 32] {
    use sha2::Digest as _;
    Sha256::digest(access_key).into()
}

/// Derive the content-encryption key (exposed for test vectors and SDK debugging).
///
/// # Errors
/// Returns an error if the password presence does not match `kdf`, or if
/// the KDF parameters are out of bounds.
#[doc(hidden)]
pub fn derive_content_key(
    key: &ShareKey,
    kdf: Option<&DecodedKdf>,
    password: Option<&str>,
) -> Result<Zeroizing<[u8; KEY_LEN]>, ProtocolError> {
    match (kdf, password) {
        (None, None) => Ok(Zeroizing::new(*key.as_bytes())),
        (Some(_), None) => Err(ProtocolError::PasswordRequired),
        (None, Some(_)) => Err(ProtocolError::PasswordNotExpected),
        (Some(k), Some(pw)) => Ok(derive_password_keys(key, k, pw)?.cek),
    }
}

/// Decrypt with an already-derived content key (avoids a second Argon2id run).
///
/// # Errors
/// [`ProtocolError::Decryption`] on authentication failure.
pub fn decrypt_with_cek(
    cek: &[u8; KEY_LEN],
    env: &DecodedEnvelope,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let aad = build_aad(env.kdf.as_ref());
    let cipher = Aes256Gcm::new_from_slice(cek).map_err(|_| ProtocolError::Kdf)?;
    cipher
        .decrypt(
            (&env.nonce).into(),
            Payload {
                msg: &env.ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| ProtocolError::Decryption)
}

/// Result of [`encrypt_payload_with_access`].
#[derive(Debug)]
pub struct EncryptedShare {
    pub envelope: DecodedEnvelope,
    /// `SHA-256(access_key)` for password-protected shares (sent to the server at creation).
    pub access_verifier: Option<[u8; 32]>,
}

/// Encrypt a payload and, when a password is given, compute the access
/// verifier from the same Argon2id evaluation.
///
/// # Errors
/// See [`encrypt`].
pub fn encrypt_payload_with_access(
    key: &ShareKey,
    payload: &SecretPayload,
    password: Option<(&str, KdfCost)>,
    pad_to: usize,
) -> Result<EncryptedShare, ProtocolError> {
    let bytes = Zeroizing::new(payload.to_bytes(pad_to)?);
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce)?;
    let Some((pw, cost)) = password else {
        return Ok(EncryptedShare {
            envelope: encrypt_deterministic(key, &bytes, nonce, None)?,
            access_verifier: None,
        });
    };
    let mut salt = [0u8; KDF_SALT_LEN];
    random_bytes(&mut salt)?;
    let kdf = DecodedKdf {
        salt,
        memory_kib: cost.memory_kib,
        iterations: cost.iterations,
        parallelism: cost.parallelism,
    };
    let keys = derive_password_keys(key, &kdf, pw)?;
    let aad = build_aad(Some(&kdf));
    let cipher = Aes256Gcm::new_from_slice(keys.cek.as_ref()).map_err(|_| ProtocolError::Kdf)?;
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &bytes,
                aad: &aad,
            },
        )
        .map_err(|_| ProtocolError::TooLarge)?;
    Ok(EncryptedShare {
        envelope: DecodedEnvelope {
            nonce,
            ciphertext,
            kdf: Some(kdf),
        },
        access_verifier: Some(access_verifier(&keys.access_key)),
    })
}

/// Low-level deterministic encryption with caller-supplied nonce and KDF salt.
///
/// **Only for test vectors and interoperability testing.** Production code must
/// use [`encrypt`], which draws a fresh random nonce and salt.
///
/// # Errors
/// Returns an error if key derivation or encryption fails.
#[doc(hidden)]
pub fn encrypt_deterministic(
    key: &ShareKey,
    plaintext: &[u8],
    nonce: [u8; NONCE_LEN],
    password: Option<(&str, DecodedKdf)>,
) -> Result<DecodedEnvelope, ProtocolError> {
    let kdf = password.as_ref().map(|(_, k)| *k);
    let cek = derive_content_key(key, kdf.as_ref(), password.map(|(p, _)| p))?;
    let aad = build_aad(kdf.as_ref());
    let cipher = Aes256Gcm::new_from_slice(cek.as_ref()).map_err(|_| ProtocolError::Kdf)?;
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| ProtocolError::TooLarge)?;
    Ok(DecodedEnvelope {
        nonce,
        ciphertext,
        kdf,
    })
}

/// Encrypt raw plaintext bytes under `key` (and optionally a password).
///
/// # Errors
/// Returns an error if the RNG, key derivation or encryption fails, or if the
/// requested KDF cost is outside the protocol bounds.
pub fn encrypt(
    key: &ShareKey,
    plaintext: &[u8],
    password: Option<(&str, KdfCost)>,
) -> Result<DecodedEnvelope, ProtocolError> {
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce)?;
    let pw = match password {
        None => None,
        Some((pw, cost)) => {
            let mut salt = [0u8; KDF_SALT_LEN];
            random_bytes(&mut salt)?;
            let k = DecodedKdf {
                salt,
                memory_kib: cost.memory_kib,
                iterations: cost.iterations,
                parallelism: cost.parallelism,
            };
            k.check_bounds()?;
            Some((pw, k))
        }
    };
    encrypt_deterministic(key, plaintext, nonce, pw)
}

/// Decrypt an envelope. Fails with [`ProtocolError::Decryption`] on a wrong
/// key, a wrong password, or any modification of ciphertext, nonce or AAD-bound fields.
///
/// # Errors
/// See above; also [`ProtocolError::PasswordRequired`] when a password is needed.
pub fn decrypt(
    key: &ShareKey,
    env: &DecodedEnvelope,
    password: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let cek = derive_content_key(key, env.kdf.as_ref(), password)?;
    let aad = build_aad(env.kdf.as_ref());
    let cipher = Aes256Gcm::new_from_slice(cek.as_ref()).map_err(|_| ProtocolError::Kdf)?;
    cipher
        .decrypt(
            (&env.nonce).into(),
            Payload {
                msg: &env.ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| ProtocolError::Decryption)
}

/// Serialize, pad and encrypt a [`SecretPayload`].
///
/// # Errors
/// See [`encrypt`].
pub fn encrypt_payload(
    key: &ShareKey,
    payload: &SecretPayload,
    password: Option<(&str, KdfCost)>,
    pad_to: usize,
) -> Result<DecodedEnvelope, ProtocolError> {
    let bytes = Zeroizing::new(payload.to_bytes(pad_to)?);
    encrypt(key, &bytes, password)
}

/// Decrypt and parse a [`SecretPayload`].
///
/// # Errors
/// See [`decrypt`]; [`ProtocolError::MalformedPayload`] if the plaintext is not a valid payload.
pub fn decrypt_payload(
    key: &ShareKey,
    env: &DecodedEnvelope,
    password: Option<&str>,
) -> Result<Zeroizing<SecretPayload>, ProtocolError> {
    let bytes = decrypt(key, env, password)?;
    SecretPayload::from_bytes(&bytes).map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap_cost() -> KdfCost {
        KdfCost {
            memory_kib: kdf_bounds::MIN_MEMORY_KIB,
            iterations: kdf_bounds::MIN_ITERATIONS,
            parallelism: 1,
        }
    }

    #[test]
    fn roundtrip_without_password() {
        let k = ShareKey::generate().unwrap();
        let env = encrypt(&k, b"synthetic secret", None).unwrap();
        assert_eq!(env.nonce.len(), 12);
        assert_eq!(env.ciphertext.len(), b"synthetic secret".len() + 16);
        assert_eq!(
            decrypt(&k, &env, None).unwrap().as_slice(),
            b"synthetic secret"
        );
    }

    #[test]
    fn roundtrip_with_password() {
        let k = ShareKey::generate().unwrap();
        let env = encrypt(&k, b"pw secret", Some(("correct horse", cheap_cost()))).unwrap();
        assert!(env.kdf.is_some());
        assert_eq!(
            decrypt(&k, &env, Some("correct horse")).unwrap().as_slice(),
            b"pw secret"
        );
        assert_eq!(
            decrypt(&k, &env, Some("wrong")),
            Err(ProtocolError::Decryption)
        );
        assert_eq!(
            decrypt(&k, &env, None),
            Err(ProtocolError::PasswordRequired)
        );
        // Password alone is not enough: a different share key fails.
        let k2 = ShareKey::generate().unwrap();
        assert_eq!(
            decrypt(&k2, &env, Some("correct horse")),
            Err(ProtocolError::Decryption)
        );
    }

    #[test]
    fn password_is_nfc_normalized() {
        let k = ShareKey::generate().unwrap();
        // "é" precomposed vs. "e" + combining acute accent
        let env = encrypt(&k, b"x", Some(("caf\u{e9}", cheap_cost()))).unwrap();
        assert!(decrypt(&k, &env, Some("cafe\u{301}")).is_ok());
    }

    #[test]
    fn unexpected_password_rejected() {
        let k = ShareKey::generate().unwrap();
        let env = encrypt(&k, b"x", None).unwrap();
        assert_eq!(
            decrypt(&k, &env, Some("pw")),
            Err(ProtocolError::PasswordNotExpected)
        );
    }

    #[test]
    fn tampering_detected() {
        let k = ShareKey::generate().unwrap();
        let env = encrypt(&k, b"integrity", None).unwrap();
        for i in 0..env.ciphertext.len() {
            let mut e = env.clone();
            e.ciphertext[i] ^= 0x01;
            assert_eq!(decrypt(&k, &e, None), Err(ProtocolError::Decryption));
        }
        let mut e = env.clone();
        e.nonce[0] ^= 1;
        assert_eq!(decrypt(&k, &e, None), Err(ProtocolError::Decryption));
        let mut e = env.clone();
        e.ciphertext.truncate(e.ciphertext.len() - 1);
        assert_eq!(decrypt(&k, &e, None), Err(ProtocolError::Decryption));
    }

    #[test]
    fn kdf_parameter_tampering_detected() {
        let k = ShareKey::generate().unwrap();
        let env = encrypt(&k, b"x", Some(("pw", cheap_cost()))).unwrap();
        let mut e = env.clone();
        e.kdf.as_mut().unwrap().iterations += 1;
        assert_eq!(decrypt(&k, &e, Some("pw")), Err(ProtocolError::Decryption));
        let mut e = env.clone();
        e.kdf.as_mut().unwrap().salt[0] ^= 1;
        assert_eq!(decrypt(&k, &e, Some("pw")), Err(ProtocolError::Decryption));
        // Stripping the KDF (downgrade) also fails authentication.
        let mut e = env;
        e.kdf = None;
        assert!(decrypt(&k, &e, None).is_err());
    }

    #[test]
    fn kdf_cost_bounds_enforced_on_encrypt() {
        let k = ShareKey::generate().unwrap();
        let bad = KdfCost {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        assert!(matches!(
            encrypt(&k, b"x", Some(("pw", bad))),
            Err(ProtocolError::KdfBounds(_))
        ));
    }

    #[test]
    fn nonces_are_unique() {
        let k = ShareKey::generate().unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(encrypt(&k, b"", None).unwrap().nonce));
        }
    }

    #[test]
    fn access_key_independent_of_cek_and_requires_key() {
        let k = ShareKey::generate().unwrap();
        let kdf = DecodedKdf {
            salt: [9; 16],
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        };
        let a = derive_password_keys(&k, &kdf, "pw").unwrap();
        assert_ne!(*a.cek, *a.access_key);
        let b = derive_password_keys(&ShareKey::generate().unwrap(), &kdf, "pw").unwrap();
        assert_ne!(
            *a.access_key, *b.access_key,
            "access key depends on the share key"
        );
        let c = derive_password_keys(&k, &kdf, "pw2").unwrap();
        assert_ne!(*a.access_key, *c.access_key);
    }

    #[test]
    fn encrypt_with_access_roundtrip() {
        let k = ShareKey::generate().unwrap();
        let s = encrypt_payload_with_access(
            &k,
            &SecretPayload::text("x"),
            Some(("pw", cheap_cost())),
            0,
        )
        .unwrap();
        let kdf = s.envelope.kdf.unwrap();
        let keys = derive_password_keys(&k, &kdf, "pw").unwrap();
        assert_eq!(
            s.access_verifier.unwrap(),
            access_verifier(&keys.access_key)
        );
        assert_eq!(
            decrypt_with_cek(&keys.cek, &s.envelope).unwrap().as_slice(),
            br#"{"content":"x"}"#
        );
        assert!(
            encrypt_payload_with_access(&k, &SecretPayload::text("x"), None, 0)
                .unwrap()
                .access_verifier
                .is_none()
        );
    }

    #[test]
    fn key_debug_redacted() {
        let k = ShareKey::from_bytes([0x41; 32]);
        let s = format!("{k:?}");
        assert!(!s.contains(k.to_b64().as_str()));
    }
}
