//! Strict, canonical base64url (RFC 4648 §5) without padding.
//!
//! Decoding rejects padding, whitespace, the standard alphabet (`+` / `/`) and
//! non-canonical trailing bits, so every byte string has exactly one accepted
//! textual representation.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::ProtocolError;

/// Encode bytes as unpadded base64url.
#[must_use]
pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode unpadded, canonical base64url.
///
/// # Errors
/// Returns [`ProtocolError::Encoding`] if `input` is not canonical unpadded base64url.
pub fn b64_decode(input: &str, field: &'static str) -> Result<Vec<u8>, ProtocolError> {
    // The `base64` crate's URL_SAFE_NO_PAD engine already rejects padding and
    // non-canonical trailing bits (`decode_allow_trailing_bits` is false).
    URL_SAFE_NO_PAD
        .decode(input.as_bytes())
        .map_err(|_| ProtocolError::Encoding(field))
}

/// Decode unpadded base64url into a fixed-size array.
///
/// # Errors
/// Returns an error if the input is malformed or does not decode to exactly `N` bytes.
pub fn b64_decode_array<const N: usize>(
    input: &str,
    field: &'static str,
) -> Result<[u8; N], ProtocolError> {
    // Cheap length pre-check before allocating: unpadded base64 of N bytes has a fixed length.
    if input.len() != encoded_len(N) {
        return Err(ProtocolError::Length(field));
    }
    let v = b64_decode(input, field)?;
    v.try_into().map_err(|_| ProtocolError::Length(field))
}

/// Length of the unpadded base64url encoding of `n` bytes.
#[must_use]
pub const fn encoded_len(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

/// Upper bound on the decoded length of an unpadded base64url string of `len` characters.
#[must_use]
pub const fn decoded_len_upper(len: usize) -> usize {
    len * 3 / 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_strictness() {
        let data = [0xfbu8, 0xff, 0x00, 0x10];
        let enc = b64_encode(&data);
        assert_eq!(enc, "-_8AEA");
        assert_eq!(b64_decode(&enc, "x").unwrap(), data);
        // padding rejected
        assert!(b64_decode("-_8AEA==", "x").is_err());
        // standard alphabet rejected
        assert!(b64_decode("+/8AEA", "x").is_err());
        // whitespace rejected
        assert!(b64_decode("-_8A EA", "x").is_err());
        // non-canonical trailing bits rejected ("-_8AEB" has non-zero padding bits)
        assert!(b64_decode("-_8AEB", "x").is_err());
    }

    #[test]
    fn encoded_lengths() {
        assert_eq!(encoded_len(12), 16);
        assert_eq!(encoded_len(16), 22);
        assert_eq!(encoded_len(32), 43);
        assert_eq!(b64_encode(&[0u8; 32]).len(), 43);
    }

    #[test]
    fn fixed_array_length_checked() {
        assert!(b64_decode_array::<12>(&b64_encode(&[1u8; 12]), "n").is_ok());
        assert!(matches!(
            b64_decode_array::<12>(&b64_encode(&[1u8; 11]), "n"),
            Err(ProtocolError::Length("n"))
        ));
    }
}
