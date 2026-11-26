//! Small helpers: time, randomness, formatting.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::ApiError;

/// Current Unix time in seconds.
#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Format Unix seconds as RFC 3339 UTC (`2025-01-01T00:00:00Z`).
#[must_use]
pub fn rfc3339(secs: u64) -> String {
    let t = i64::try_from(secs)
        .ok()
        .and_then(|s| time::OffsetDateTime::from_unix_timestamp(s).ok())
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// `N` random bytes from the OS CSPRNG.
///
/// # Errors
/// [`ApiError::Internal`] if the RNG is unavailable.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], ApiError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| ApiError::Internal)?;
    Ok(b)
}

/// `N` random bytes, unpadded base64url-encoded.
///
/// # Errors
/// [`ApiError::Internal`] if the RNG is unavailable.
pub fn random_b64<const N: usize>() -> Result<String, ApiError> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes::<N>()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_format() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn randomness_differs() {
        assert_ne!(random_bytes::<16>().unwrap(), random_bytes::<16>().unwrap());
        assert_eq!(random_b64::<16>().unwrap().len(), 22);
    }
}
