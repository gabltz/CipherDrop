//! The plaintext document that is encrypted.
//!
//! Every piece of user-controlled data (content, title, formatting
//! preferences) lives inside the encrypted payload; nothing user-defined is
//! sent to the server in the clear.
//!
//! Wire form: a UTF-8 JSON object, optionally followed by ASCII space
//! padding (which every JSON parser ignores) to hide the exact plaintext length:
//!
//! ```json
//! {"content":"…","title":"…","syntax":"rust"}
//! ```
//!
//! Unknown fields MUST be ignored by readers for forward compatibility.

use serde::{Deserialize, Serialize};

use crate::ProtocolError;

/// Maximum length (in bytes) of the optional syntax/language hint.
pub const MAX_SYNTAX_LEN: usize = 32;

/// Plaintext share content.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SecretPayload {
    /// The secret text.
    pub content: String,
    /// Optional title (encrypted like everything else).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional syntax-highlighting hint, e.g. `rust`, `json`, `plaintext`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syntax: Option<String>,
}

impl core::fmt::Debug for SecretPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretPayload")
            .field("content", &"<redacted>")
            .field("title", &self.title.as_ref().map(|_| "<redacted>"))
            .field("syntax", &self.syntax)
            .finish()
    }
}

#[cfg(feature = "crypto")]
impl zeroize::Zeroize for SecretPayload {
    fn zeroize(&mut self) {
        self.content.zeroize();
        if let Some(t) = self.title.as_mut() {
            t.zeroize();
        }
        if let Some(s) = self.syntax.as_mut() {
            s.zeroize();
        }
    }
}

impl SecretPayload {
    /// Plain text without title or syntax hint.
    #[must_use]
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            ..Self::default()
        }
    }

    /// Serialize to compact JSON, then pad with ASCII spaces up to the next
    /// multiple of `pad_to` bytes (`pad_to == 0` disables padding).
    ///
    /// # Errors
    /// Fails only if JSON serialization fails.
    pub fn to_bytes(&self, pad_to: usize) -> Result<Vec<u8>, ProtocolError> {
        let mut v = serde_json::to_vec(self).map_err(|_| ProtocolError::MalformedPayload)?;
        if pad_to > 0 {
            let target = v.len().div_ceil(pad_to) * pad_to;
            v.resize(target, b' ');
        }
        Ok(v)
    }

    /// Parse plaintext bytes. Trailing ASCII whitespace padding is accepted.
    ///
    /// # Errors
    /// Returns [`ProtocolError::MalformedPayload`] for invalid UTF-8/JSON or an
    /// overlong syntax hint.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let p: Self = serde_json::from_slice(bytes).map_err(|_| ProtocolError::MalformedPayload)?;
        if p.syntax.as_ref().is_some_and(|s| s.len() > MAX_SYNTAX_LEN) {
            return Err(ProtocolError::MalformedPayload);
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_roundtrip() {
        let p = SecretPayload {
            content: "héllo".into(),
            title: Some("t".into()),
            syntax: Some("rust".into()),
        };
        let b = p.to_bytes(256).unwrap();
        assert_eq!(b.len(), 256);
        assert_eq!(SecretPayload::from_bytes(&b).unwrap(), p);
        let b = p.to_bytes(0).unwrap();
        assert_eq!(
            String::from_utf8(b).unwrap(),
            r#"{"content":"héllo","title":"t","syntax":"rust"}"#
        );
    }

    #[test]
    fn unknown_fields_ignored() {
        let p = SecretPayload::from_bytes(br#"{"content":"x","future":true}  "#).unwrap();
        assert_eq!(p.content, "x");
    }

    #[test]
    fn rejects_garbage() {
        assert!(SecretPayload::from_bytes(b"not json").is_err());
        assert!(SecretPayload::from_bytes(&[0xff, 0xfe]).is_err());
        assert!(SecretPayload::from_bytes(br#"{"title":"x"}"#).is_err());
    }

    #[test]
    fn debug_redacts() {
        let s = format!("{:?}", SecretPayload::text("topsecret"));
        assert!(!s.contains("topsecret"));
    }
}
