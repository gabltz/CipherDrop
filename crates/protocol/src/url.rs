//! Share identifiers and capability URLs.
//!
//! ```text
//! share link:      {public_url}/s/{share_id}#v1.{share_key}
//! revocation link: {public_url}/revoke/{share_id}#v1.{revocation_token}
//! ```
//!
//! * `share_id`: 16 random bytes, unpadded base64url (22 characters).
//! * `share_key`: 32 random bytes, unpadded base64url (43 characters).
//! * `revocation_token`: 32 random bytes, unpadded base64url (43 characters).
//!
//! Everything after `#` is a URL fragment: browsers never send it to the
//! server. Clients MUST strip the fragment before making any HTTP request.

use core::fmt;

use crate::encoding::{b64_decode_array, b64_encode};
use crate::{ProtocolError, REVOCATION_TOKEN_LEN, SHARE_ID_LEN};

/// Path segment preceding the share id in share links.
pub const SHARE_PATH: &str = "/s/";
/// Path segment preceding the share id in revocation links.
pub const REVOKE_PATH: &str = "/revoke/";
/// Fragment prefix identifying a v1 capability.
pub const FRAGMENT_PREFIX: &str = "v1.";

/// A validated share identifier (128 random bits).
///
/// `Debug` and `Display` intentionally differ: `Debug` prints only a short
/// non-reversible tag so that share identifiers do not end up in logs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShareId([u8; SHARE_ID_LEN]);

impl ShareId {
    #[must_use]
    pub const fn from_bytes(b: [u8; SHARE_ID_LEN]) -> Self {
        Self(b)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHARE_ID_LEN] {
        &self.0
    }

    /// Parse the 22-character textual form.
    ///
    /// # Errors
    /// Returns [`ProtocolError::MalformedUrl`] if the identifier is malformed.
    pub fn parse(s: &str) -> Result<Self, ProtocolError> {
        b64_decode_array::<SHARE_ID_LEN>(s, "share_id")
            .map(Self)
            .map_err(|_| ProtocolError::MalformedUrl)
    }
}

impl fmt::Display for ShareId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&b64_encode(&self.0))
    }
}

impl fmt::Debug for ShareId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShareId(<redacted>)")
    }
}

/// Split a link of the form `{base}{path_marker}{id}#v1.{secret}` or the short
/// form `{id}#v1.{secret}`. Returns `(base_url, id, secret_text)`.
fn split_link<'a>(
    link: &'a str,
    path_marker: &str,
) -> Result<(Option<&'a str>, ShareId, &'a str), ProtocolError> {
    let link = link.trim();
    let (left, fragment) = link.split_once('#').ok_or(ProtocolError::MalformedUrl)?;
    let secret = fragment
        .strip_prefix(FRAGMENT_PREFIX)
        .ok_or(ProtocolError::MalformedUrl)?;
    let (base, id_str) = match left.rfind(path_marker) {
        Some(pos) => {
            let base = &left[..pos];
            if !(base.starts_with("https://") || base.starts_with("http://")) {
                return Err(ProtocolError::MalformedUrl);
            }
            (Some(base), &left[pos + path_marker.len()..])
        }
        None if !left.contains('/') && !left.contains(':') => (None, left),
        None => return Err(ProtocolError::MalformedUrl),
    };
    // Tolerate a trailing slash or query string? No: be strict, reject anything extra.
    let id = ShareId::parse(id_str)?;
    Ok((base, id, secret))
}

/// A parsed revocation link (`{base}/revoke/{id}#v1.{token}`).
#[derive(Clone, PartialEq, Eq)]
pub struct RevocationLink {
    pub base_url: Option<String>,
    pub share_id: ShareId,
    /// The revocation token in its textual (base64url) form.
    pub token: String,
}

impl fmt::Debug for RevocationLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationLink")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl RevocationLink {
    /// Parse a revocation link.
    ///
    /// # Errors
    /// Returns [`ProtocolError::MalformedUrl`] for malformed links.
    pub fn parse(link: &str) -> Result<Self, ProtocolError> {
        let (base, share_id, token) = split_link(link, REVOKE_PATH)?;
        validate_revocation_token(token)?;
        Ok(Self {
            base_url: base.map(str::to_owned),
            share_id,
            token: token.to_owned(),
        })
    }

    #[must_use]
    pub fn format(base_url: &str, share_id: &ShareId, token: &str) -> String {
        format!(
            "{}{REVOKE_PATH}{share_id}#{FRAGMENT_PREFIX}{token}",
            base_url.trim_end_matches('/')
        )
    }
}

/// Validate the textual form of a revocation token (43-char base64url of 32 bytes).
///
/// # Errors
/// Returns [`ProtocolError::MalformedUrl`] for malformed tokens.
pub fn validate_revocation_token(token: &str) -> Result<(), ProtocolError> {
    b64_decode_array::<REVOCATION_TOKEN_LEN>(token, "revocation_token")
        .map(|_| ())
        .map_err(|_| ProtocolError::MalformedUrl)
}

/// Format a fragment-free share URL (as returned by the server).
#[must_use]
pub fn share_url_without_key(base_url: &str, share_id: &ShareId) -> String {
    format!("{}{SHARE_PATH}{share_id}", base_url.trim_end_matches('/'))
}

#[cfg(feature = "crypto")]
pub use share_link::ShareLink;

#[cfg(feature = "crypto")]
mod share_link {
    use super::*;
    use crate::crypto::ShareKey;

    /// A parsed share link: base URL (if present), share id and share key.
    #[derive(Debug)]
    pub struct ShareLink {
        pub base_url: Option<String>,
        pub share_id: ShareId,
        pub key: ShareKey,
    }

    impl ShareLink {
        /// Parse a complete share link (`https://host/s/{id}#v1.{key}`) or the
        /// short form `{id}#v1.{key}`.
        ///
        /// # Errors
        /// Returns [`ProtocolError::MalformedUrl`] if the link is malformed.
        pub fn parse(link: &str) -> Result<Self, ProtocolError> {
            let (base, share_id, key) = split_link(link, SHARE_PATH)?;
            let key = ShareKey::from_b64(key).map_err(|_| ProtocolError::MalformedUrl)?;
            Ok(Self {
                base_url: base.map(str::to_owned),
                share_id,
                key,
            })
        }

        /// Format a complete share link including the key fragment.
        #[must_use]
        pub fn format(base_url: &str, share_id: &ShareId, key: &ShareKey) -> String {
            format!(
                "{}#{FRAGMENT_PREFIX}{}",
                share_url_without_key(base_url, share_id),
                key.to_b64().as_str()
            )
        }

        /// Append the key fragment to a fragment-free share URL returned by the server.
        ///
        /// # Errors
        /// Returns [`ProtocolError::MalformedUrl`] if `url` already contains a fragment.
        pub fn attach_key(url: &str, key: &ShareKey) -> Result<String, ProtocolError> {
            if url.contains('#') {
                return Err(ProtocolError::MalformedUrl);
            }
            Ok(format!("{url}#{FRAGMENT_PREFIX}{}", key.to_b64().as_str()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "AAECAwQFBgcICQoLDA0ODw";
    const TOKEN: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    #[test]
    fn share_id_roundtrip_and_debug_redaction() {
        let id = ShareId::parse(ID).unwrap();
        assert_eq!(id.to_string(), ID);
        assert!(!format!("{id:?}").contains(ID));
        assert!(ShareId::parse("short").is_err());
        assert!(ShareId::parse(&format!("{ID}A")).is_err());
    }

    #[test]
    fn revocation_link() {
        let link =
            RevocationLink::format("https://x.example/", &ShareId::parse(ID).unwrap(), TOKEN);
        assert_eq!(link, format!("https://x.example/revoke/{ID}#v1.{TOKEN}"));
        let r = RevocationLink::parse(&link).unwrap();
        assert_eq!(r.base_url.as_deref(), Some("https://x.example"));
        assert_eq!(r.token, TOKEN);
        assert!(RevocationLink::parse(&format!("{ID}#v1.{TOKEN}")).is_ok());
        assert!(RevocationLink::parse(&format!("{ID}#v2.{TOKEN}")).is_err());
        assert!(RevocationLink::parse(&format!("https://x.example/s/{ID}#v1.{TOKEN}")).is_err());
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn share_link_parse() {
        let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let l = ShareLink::parse(&format!("https://paste.example.com/s/{ID}#v1.{key}")).unwrap();
        assert_eq!(l.base_url.as_deref(), Some("https://paste.example.com"));
        assert_eq!(l.share_id.to_string(), ID);
        assert_eq!(l.key.to_b64().as_str(), key);
        // subpath deployments
        let l = ShareLink::parse(&format!("https://h.example/paste/s/{ID}#v1.{key}")).unwrap();
        assert_eq!(l.base_url.as_deref(), Some("https://h.example/paste"));
        // short form
        assert!(ShareLink::parse(&format!("{ID}#v1.{key}")).is_ok());
        // malformed
        for bad in [
            format!("https://h/s/{ID}"),
            format!("https://h/s/{ID}#{key}"),
            format!("https://h/s/{ID}?x=1#v1.{key}"),
            format!("ftp://h/s/{ID}#v1.{key}"),
            format!("https://h/s/{ID}#v1.{key}A"),
        ] {
            assert!(ShareLink::parse(&bad).is_err(), "{bad}");
        }
    }
}
