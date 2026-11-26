//! Canonical AES-GCM associated data (AAD) for protocol v1.
//!
//! The AAD binds the protocol version, the algorithm and every public key
//! derivation parameter to the ciphertext. Any modification of these
//! envelope fields by the server or a network attacker makes authentication
//! fail on the recipient's device.
//!
//! The AAD is the ASCII encoding of:
//!
//! ```text
//! no password:   cipherdrop/v1;alg=AES-256-GCM;kdf=none
//! with password: cipherdrop/v1;alg=AES-256-GCM;kdf=argon2id;v=19;m=<m>;t=<t>;p=<p>;salt=<salt>
//! ```
//!
//! Integers are base-10 without leading zeros or signs; `<salt>` is the
//! canonical unpadded base64url encoding of the 16 salt bytes; `v=19` is
//! Argon2 version 0x13.

use crate::encoding::b64_encode;
use crate::envelope::DecodedKdf;

/// Prefix shared by all v1 AAD strings.
pub const AAD_PREFIX: &str = "cipherdrop/v1;alg=AES-256-GCM;kdf=";

/// Build the canonical AAD bytes for an envelope.
#[must_use]
pub fn build_aad(kdf: Option<&DecodedKdf>) -> Vec<u8> {
    let s = match kdf {
        None => format!("{AAD_PREFIX}none"),
        Some(k) => format!(
            "{AAD_PREFIX}argon2id;v=19;m={};t={};p={};salt={}",
            k.memory_kib,
            k.iterations,
            k.parallelism,
            b64_encode(&k.salt)
        ),
    };
    s.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_strings() {
        assert_eq!(build_aad(None), b"cipherdrop/v1;alg=AES-256-GCM;kdf=none");
        let k = DecodedKdf {
            salt: [0u8; 16],
            memory_kib: 65536,
            iterations: 3,
            parallelism: 1,
        };
        assert_eq!(
            String::from_utf8(build_aad(Some(&k))).unwrap(),
            "cipherdrop/v1;alg=AES-256-GCM;kdf=argon2id;v=19;m=65536;t=3;p=1;salt=AAAAAAAAAAAAAAAAAAAAAA"
        );
    }
}
