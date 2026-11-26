//! JSON request and response types for the `/api/v1` REST API.
//!
//! These types are shared by the server, the Rust SDK and the CLI, and they
//! generate the OpenAPI schema (feature `openapi`).

use serde::{Deserialize, Deserializer, Serialize};

use crate::envelope::{Algorithm, EncryptedEnvelope, KdfParams};

/// Deserialize helper distinguishing an absent field (`None`) from an
/// explicit `null` (`Some(None)`).
fn double_option<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

/// Storage backend for a share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum StorageBackend {
    /// Volatile RAM-only storage (default). Lost on restart.
    #[default]
    Memory,
    /// SQLite-backed storage. Must be enabled by the administrator and requires
    /// the `shares:create:persistent` scope.
    Persistent,
}

/// Request body of `POST /api/v1/shares`.
///
/// The client encrypts locally and uploads only the envelope; the server never
/// receives plaintext, keys or passwords.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateShareRequest {
    /// Protocol version; must be `1`.
    #[cfg_attr(feature = "openapi", schema(example = 1))]
    pub version: u8,
    pub algorithm: Algorithm,
    /// 12-byte nonce, unpadded base64url.
    #[cfg_attr(feature = "openapi", schema(example = "AAECAwQFBgcICQoL"))]
    pub nonce: String,
    /// Ciphertext with appended 16-byte GCM tag, unpadded base64url.
    pub ciphertext: String,
    /// Argon2id parameters, present only for password-protected shares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<KdfParams>,
    /// Lifetime in seconds. Omit for the instance default. `null` requests a
    /// share that never expires (requires `allow_permanent` and the
    /// `shares:create:persistent` scope).
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<u64>, example = 3600))]
    pub ttl_seconds: Option<Option<u64>>,
    /// Maximum number of successful retrievals. Omit for the instance default.
    /// `null` means unlimited (requires `allow_unlimited_reads`).
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<u32>, example = 1))]
    pub max_reads: Option<Option<u32>>,
    /// Storage backend; defaults to `memory`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageBackend>,
}

impl CreateShareRequest {
    /// Build a request from an envelope with instance-default limits.
    #[must_use]
    pub fn from_envelope(env: EncryptedEnvelope) -> Self {
        Self {
            version: env.version,
            algorithm: env.algorithm,
            nonce: env.nonce,
            ciphertext: env.ciphertext,
            kdf: env.kdf,
            ttl_seconds: None,
            max_reads: None,
            storage: None,
        }
    }

    /// Borrow the envelope part of the request.
    #[must_use]
    pub fn envelope(&self) -> EncryptedEnvelope {
        EncryptedEnvelope {
            version: self.version,
            algorithm: self.algorithm,
            nonce: self.nonce.clone(),
            ciphertext: self.ciphertext.clone(),
            kdf: self.kdf.clone(),
        }
    }
}

/// Response of `POST /api/v1/shares` (HTTP 201).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateShareResponse {
    /// Opaque share identifier (22 characters).
    #[cfg_attr(feature = "openapi", schema(example = "AAECAwQFBgcICQoLDA0ODw"))]
    pub id: String,
    /// Share URL **without** key. The client appends `#v1.{key}` locally.
    #[cfg_attr(
        feature = "openapi",
        schema(example = "https://paste.example.com/s/AAECAwQFBgcICQoLDA0ODw")
    )]
    pub url: String,
    /// Creation time (RFC 3339, UTC).
    pub created_at: String,
    /// Expiration time (RFC 3339, UTC), or `null` for permanent shares.
    pub expires_at: Option<String>,
    /// Maximum retrievals, or `null` for unlimited.
    pub max_reads: Option<u32>,
    pub storage: StorageBackend,
    /// Secret capability that allows revoking this share. Shown only once;
    /// keep it away from recipients.
    pub revocation_token: String,
    /// Convenience link `{public_url}/revoke/{id}#v1.{revocation_token}`.
    pub revocation_url: String,
}

/// Response of `POST /api/v1/shares/{id}/consume`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConsumeShareResponse {
    #[cfg_attr(feature = "openapi", schema(example = 1))]
    pub version: u8,
    pub algorithm: Algorithm,
    pub nonce: String,
    pub ciphertext: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<KdfParams>,
    /// Retrievals left after this one (`0` means the share has been deleted),
    /// or `null` for unlimited.
    pub remaining_reads: Option<u32>,
    /// Expiration time (RFC 3339), or `null`.
    pub expires_at: Option<String>,
}

impl ConsumeShareResponse {
    #[must_use]
    pub fn envelope(&self) -> EncryptedEnvelope {
        EncryptedEnvelope {
            version: self.version,
            algorithm: self.algorithm,
            nonce: self.nonce.clone(),
            ciphertext: self.ciphertext.clone(),
            kdf: self.kdf.clone(),
        }
    }
}

/// Response of `GET /api/v1/shares/{id}/status` (non-consuming).
///
/// Unavailable shares (unknown, expired, consumed or revoked) all yield the
/// same `404` problem response; the server keeps no tombstones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ShareStatusResponse {
    /// Always `true` in a 200 response.
    pub available: bool,
    pub expires_at: Option<String>,
    pub remaining_reads: Option<u32>,
    /// Whether the recipient will need a password in addition to the link.
    pub password_protected: bool,
    pub storage: StorageBackend,
}

/// Public Argon2id bounds and defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct KdfLimits {
    pub min_memory_kib: u32,
    pub max_memory_kib: u32,
    pub min_iterations: u32,
    pub max_iterations: u32,
    pub min_parallelism: u32,
    pub max_parallelism: u32,
    pub default_memory_kib: u32,
    pub default_iterations: u32,
    pub default_parallelism: u32,
}

impl Default for KdfLimits {
    fn default() -> Self {
        use crate::envelope::kdf_bounds::*;
        Self {
            min_memory_kib: MIN_MEMORY_KIB,
            max_memory_kib: MAX_MEMORY_KIB,
            min_iterations: MIN_ITERATIONS,
            max_iterations: MAX_ITERATIONS,
            min_parallelism: MIN_PARALLELISM,
            max_parallelism: MAX_PARALLELISM,
            default_memory_kib: DEFAULT_MEMORY_KIB,
            default_iterations: DEFAULT_ITERATIONS,
            default_parallelism: DEFAULT_PARALLELISM,
        }
    }
}

/// Response of `GET /api/v1/config`: public instance capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConfigResponse {
    pub public_url: String,
    pub protocol_versions: Vec<u8>,
    /// Maximum decoded ciphertext size (bytes, including the 16-byte tag).
    pub max_ciphertext_bytes: u64,
    pub default_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub default_max_reads: u32,
    pub max_reads: u32,
    pub allow_unlimited_reads: bool,
    pub allow_permanent: bool,
    pub persistent_enabled: bool,
    pub anonymous_creation: bool,
    pub anonymous_retrieval: bool,
    pub kdf: KdfLimits,
}

/// Response of `GET /api/v1/version`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VersionResponse {
    pub name: String,
    pub version: String,
    pub api_version: String,
    pub protocol_versions: Vec<u8>,
    pub algorithms: Vec<String>,
}

/// RFC 9457 Problem Details, used for every error response
/// (`Content-Type: application/problem+json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Problem {
    /// URI identifying the problem type, e.g. `https://cipherdrop.dev/problems/share-unavailable`.
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Stable machine-readable error code, e.g. `share_unavailable`.
    pub code: String,
}

/// API token scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum Scope {
    #[serde(rename = "shares:create")]
    SharesCreate,
    #[serde(rename = "shares:create:persistent")]
    SharesCreatePersistent,
    #[serde(rename = "shares:consume")]
    SharesConsume,
    #[serde(rename = "shares:revoke")]
    SharesRevoke,
    #[serde(rename = "admin:metrics")]
    AdminMetrics,
    #[serde(rename = "admin:manage")]
    AdminManage,
}

impl Scope {
    pub const ALL: [Self; 6] = [
        Self::SharesCreate,
        Self::SharesCreatePersistent,
        Self::SharesConsume,
        Self::SharesRevoke,
        Self::AdminMetrics,
        Self::AdminManage,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SharesCreate => "shares:create",
            Self::SharesCreatePersistent => "shares:create:persistent",
            Self::SharesConsume => "shares:consume",
            Self::SharesRevoke => "shares:revoke",
            Self::AdminMetrics => "admin:metrics",
            Self::AdminManage => "admin:manage",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.as_str() == s)
    }
}

/// Request body of `POST /api/v1/admin/tokens`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateTokenRequest {
    /// Human-readable label (1..=64 characters).
    pub name: String,
    pub scopes: Vec<Scope>,
    /// Token lifetime in seconds; omit for no expiry.
    #[serde(default)]
    pub expires_in_seconds: Option<u64>,
    /// Per-token request rate limit; omit for the instance default.
    #[serde(default)]
    pub rate_limit_per_minute: Option<u32>,
    /// Maximum shares this token may create per rolling UTC day; omit for unlimited.
    #[serde(default)]
    pub daily_create_quota: Option<u32>,
}

/// Public metadata of an API token (never includes the secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TokenInfo {
    /// Public token identifier (also the prefix of the secret token).
    pub id: String,
    pub name: String,
    pub scopes: Vec<Scope>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub rate_limit_per_minute: Option<u32>,
    pub daily_create_quota: Option<u32>,
    /// `config` for tokens declared in the configuration file (immutable),
    /// `api` for tokens created through the admin API.
    pub source: String,
}

/// Response of `POST /api/v1/admin/tokens`. The secret is shown exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateTokenResponse {
    /// The bearer token. Store it now: the server keeps only a verifier.
    pub token: String,
    pub info: TokenInfo,
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#""version":1,"algorithm":"AES-256-GCM","nonce":"n","ciphertext":"c""#;

    #[test]
    fn ttl_absent_null_and_value_are_distinct() {
        let r: CreateShareRequest = serde_json::from_str(&format!("{{{BASE}}}")).unwrap();
        assert_eq!(r.ttl_seconds, None);
        let r: CreateShareRequest =
            serde_json::from_str(&format!("{{{BASE},\"ttl_seconds\":null}}")).unwrap();
        assert_eq!(r.ttl_seconds, Some(None));
        let r: CreateShareRequest =
            serde_json::from_str(&format!("{{{BASE},\"ttl_seconds\":60,\"max_reads\":3}}"))
                .unwrap();
        assert_eq!(r.ttl_seconds, Some(Some(60)));
        assert_eq!(r.max_reads, Some(Some(3)));
    }

    #[test]
    fn create_request_rejects_unknown_fields() {
        // In particular, there is no way to smuggle a plaintext or key field.
        for extra in ["\"plaintext\":\"x\"", "\"key\":\"x\"", "\"password\":\"x\""] {
            assert!(
                serde_json::from_str::<CreateShareRequest>(&format!("{{{BASE},{extra}}}")).is_err()
            );
        }
    }

    #[test]
    fn create_request_rejects_negative_ttl() {
        assert!(
            serde_json::from_str::<CreateShareRequest>(&format!("{{{BASE},\"ttl_seconds\":-1}}"))
                .is_err()
        );
    }

    #[test]
    fn scopes_roundtrip() {
        for s in Scope::ALL {
            assert_eq!(Scope::parse(s.as_str()), Some(s));
            let j = serde_json::to_string(&s).unwrap();
            assert_eq!(j, format!("\"{}\"", s.as_str()));
        }
        assert_eq!(Scope::parse("admin:*"), None);
    }
}
