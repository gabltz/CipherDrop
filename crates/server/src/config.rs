//! Configuration: TOML file plus `CIPHERDROP__SECTION__KEY` environment overrides.
//!
//! Every setting has a secure default. [`Config::validate`] runs at startup
//! and refuses incompatible or unsafe combinations instead of guessing.

use std::net::SocketAddr;
use std::path::PathBuf;

use cipherdrop_protocol::api::Scope;
use ipnet::IpNet;
use serde::Deserialize;

pub const MIB: u64 = 1024 * 1024;
const ENV_PREFIX: &str = "CIPHERDROP__";

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub shares: SharesConfig,
    pub auth: AuthConfig,
    pub security: SecurityConfig,
    pub rate_limit: RateLimitConfig,
    pub cors: CorsConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    /// Public base URL used to build share links. Never derived from `Host`.
    pub public_url: String,
    pub tls: Option<TlsConfig>,
    /// Maximum requests processed concurrently; excess requests get `503`.
    pub max_concurrent_requests: usize,
    /// Maximum requests processed concurrently for one client IP (`429` beyond).
    pub max_concurrent_requests_per_ip: usize,
    /// Maximum open TCP connections (new connections are refused beyond).
    pub max_connections: usize,
    /// Maximum open TCP connections per peer IP (trusted proxies are exempt).
    pub max_connections_per_ip: usize,
    /// Time allowed to receive complete request headers, including while an
    /// idle keep-alive connection waits for its next request.
    pub header_read_timeout_seconds: u64,
    pub shutdown_grace_seconds: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            public_url: String::new(),
            tls: None,
            max_concurrent_requests: 256,
            max_concurrent_requests_per_ip: 32,
            max_connections: 4096,
            max_connections_per_ip: 64,
            header_read_timeout_seconds: 10,
            shutdown_grace_seconds: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    #[default]
    Memory,
    Persistent,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StorageConfig {
    pub default_backend: Backend,
    /// RAM budget for stored shares (ciphertext plus per-entry overhead).
    pub max_memory_mb: u64,
    pub max_shares: usize,
    pub reject_when_full: bool,
    /// Allow `storage = "persistent"` shares (requires `sqlite_path`).
    pub persistent_enabled: bool,
    /// SQLite database for persistent shares and admin-created API tokens.
    pub sqlite_path: Option<PathBuf>,
    pub persistent_max_mb: u64,
    pub persistent_max_shares: u64,
    pub cleanup_interval_seconds: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            default_backend: Backend::Memory,
            max_memory_mb: 128,
            max_shares: 10_000,
            reject_when_full: true,
            persistent_enabled: false,
            sqlite_path: None,
            persistent_max_mb: 1024,
            persistent_max_shares: 100_000,
            cleanup_interval_seconds: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SharesConfig {
    /// Maximum decoded ciphertext size in bytes (including the 16-byte tag).
    pub max_size_bytes: u64,
    pub min_ttl_seconds: u64,
    pub default_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub default_max_reads: u32,
    pub max_reads: u32,
    /// Allow `ttl_seconds: null` (never expires) for callers with `shares:create:persistent`.
    pub allow_permanent: bool,
    /// Allow `max_reads: null` (unlimited retrievals until expiry).
    pub allow_unlimited_reads: bool,
    /// Wrong access-password attempts after which a share is destroyed.
    pub max_access_failures: u32,
}

impl Default for SharesConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: MIB,
            min_ttl_seconds: 60,
            default_ttl_seconds: 3600,
            max_ttl_seconds: 7 * 24 * 3600,
            default_max_reads: 1,
            max_reads: 100,
            allow_permanent: false,
            allow_unlimited_reads: false,
            max_access_failures: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthConfig {
    pub anonymous_creation: bool,
    pub anonymous_retrieval: bool,
    /// Static tokens; only verifiers are stored here (see `cipherdrop-server token generate`).
    pub tokens: Vec<StaticToken>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            anonymous_creation: false,
            anonymous_retrieval: true,
            tokens: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticToken {
    /// 12 lowercase hex characters (the public part of `cdt_{id}_{secret}`).
    pub id: String,
    pub name: String,
    /// Hex SHA-256 of the complete token string.
    pub sha256: String,
    pub scopes: Vec<String>,
    /// RFC 3339 expiry; omit for none.
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub rate_limit_per_minute: Option<u32>,
    #[serde(default)]
    pub daily_create_quota: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SecurityConfig {
    /// Refuse to start unless HTTPS is guaranteed (native TLS, a trusted proxy
    /// reporting `X-Forwarded-Proto: https`, or a loopback-only listener).
    pub require_https: bool,
    pub request_timeout_seconds: u64,
    /// Honour `X-Forwarded-For` / `X-Forwarded-Proto` from `trusted_proxies` only.
    pub trust_forwarded_headers: bool,
    pub trusted_proxies: Vec<IpNet>,
    /// Best effort: `RLIMIT_CORE = 0` and (Linux) `PR_SET_DUMPABLE = 0`.
    pub disable_core_dumps: bool,
    /// Best effort `mlockall` to keep process memory out of swap (needs `CAP_IPC_LOCK`).
    pub lock_memory: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_https: true,
            request_timeout_seconds: 15,
            trust_forwarded_headers: false,
            trusted_proxies: Vec::new(),
            disable_core_dumps: true,
            lock_memory: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RateLimitConfig {
    pub enabled: bool,
    /// Share creations per minute per client IP (anonymous callers).
    pub create_per_minute: u32,
    /// Consume/status/revoke requests per minute per client IP.
    pub read_per_minute: u32,
    /// Requests per minute per API token, unless overridden on the token.
    pub token_default_per_minute: u32,
    /// IPv6 clients are grouped by this prefix length.
    pub ipv6_prefix_len: u8,
    pub idempotency_ttl_seconds: u64,
    pub idempotency_max_entries: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            create_per_minute: 30,
            read_per_minute: 120,
            token_default_per_minute: 600,
            ipv6_prefix_len: 64,
            idempotency_ttl_seconds: 600,
            idempotency_max_entries: 10_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct CorsConfig {
    /// Exact origins (`https://app.example.com`) allowed to call the API from
    /// browsers. Empty = deny all cross-origin requests.
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Json,
    Text,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingConfig {
    pub level: String,
    pub format: LogFormat,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "warn".into(),
            format: LogFormat::Json,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MetricsConfig {
    pub enabled: bool,
    /// Require a bearer token with `admin:metrics`. Disable only when the
    /// endpoint is otherwise unreachable from untrusted networks.
    pub require_token: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_token: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read configuration file: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid configuration: {0}")]
    Parse(String),
    #[error("unsafe or inconsistent configuration: {0}")]
    Invalid(String),
}

fn invalid(msg: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(msg.into())
}

impl Config {
    /// Load from an optional TOML file, then apply environment overrides.
    ///
    /// # Errors
    /// Returns a [`ConfigError`] for unreadable/invalid files or overrides.
    pub fn load(path: Option<&std::path::Path>) -> Result<Self, ConfigError> {
        let text = match path {
            Some(p) => std::fs::read_to_string(p)?,
            None => String::new(),
        };
        Self::from_toml_with_env(&text, std::env::vars())
    }

    /// Parse TOML text and apply `CIPHERDROP__SECTION__KEY=value` overrides.
    ///
    /// # Errors
    /// Returns [`ConfigError::Parse`] for malformed input.
    pub fn from_toml_with_env(
        text: &str,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        let mut table: toml::Table =
            toml::from_str(text).map_err(|e| ConfigError::Parse(e.message().to_owned()))?;
        for (k, v) in env {
            let Some(rest) = k.strip_prefix(ENV_PREFIX) else {
                continue;
            };
            let path: Vec<String> = rest.split("__").map(str::to_ascii_lowercase).collect();
            if path.len() < 2 || path.iter().any(String::is_empty) {
                return Err(ConfigError::Parse(format!(
                    "malformed environment override {k}"
                )));
            }
            let value = parse_env_value(&v);
            let mut cur = &mut table;
            for seg in &path[..path.len() - 1] {
                cur = cur
                    .entry(seg.clone())
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                    .as_table_mut()
                    .ok_or_else(|| {
                        ConfigError::Parse(format!("override {k} conflicts with a non-table value"))
                    })?;
            }
            cur.insert(path[path.len() - 1].clone(), value);
        }
        toml::Value::Table(table)
            .try_into()
            .map_err(|e: toml::de::Error| ConfigError::Parse(e.message().to_owned()))
    }

    /// Validate the configuration, failing closed on unsafe settings.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] describing the first problem found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // --- public URL / HTTPS ---
        if self.server.public_url.is_empty() {
            return Err(invalid(
                "server.public_url is required (share links are never derived from the Host header)",
            ));
        }
        let u = url::Url::parse(&self.server.public_url)
            .map_err(|_| invalid("server.public_url is not a valid absolute URL"))?;
        if !matches!(u.scheme(), "https" | "http") || u.host().is_none() {
            return Err(invalid(
                "server.public_url must be an http(s) URL with a host",
            ));
        }
        if u.query().is_some()
            || u.fragment().is_some()
            || !u.username().is_empty()
            || u.password().is_some()
        {
            return Err(invalid(
                "server.public_url must not contain credentials, a query or a fragment",
            ));
        }
        if self.security.require_https {
            if u.scheme() != "https" {
                return Err(invalid(
                    "security.require_https is enabled but server.public_url is not https://",
                ));
            }
            let loopback = self.server.listen.ip().is_loopback();
            if self.server.tls.is_none() && !self.security.trust_forwarded_headers && !loopback {
                return Err(invalid(
                    "security.require_https: plain HTTP listener on a non-loopback address. Configure \
                     [server.tls], or a trusted reverse proxy (security.trust_forwarded_headers + \
                     trusted_proxies), or listen on 127.0.0.1 behind a local proxy",
                ));
            }
        }
        if self.security.trust_forwarded_headers && self.security.trusted_proxies.is_empty() {
            return Err(invalid(
                "security.trust_forwarded_headers requires security.trusted_proxies",
            ));
        }
        if !(1..=300).contains(&self.security.request_timeout_seconds) {
            return Err(invalid(
                "security.request_timeout_seconds must be within 1..=300",
            ));
        }
        if self.server.max_concurrent_requests == 0 || self.server.max_concurrent_requests > 100_000
        {
            return Err(invalid(
                "server.max_concurrent_requests must be within 1..=100000",
            ));
        }
        let srv = &self.server;
        if srv.max_concurrent_requests_per_ip == 0
            || srv.max_concurrent_requests_per_ip > srv.max_concurrent_requests
        {
            return Err(invalid(
                "server.max_concurrent_requests_per_ip must be within 1..=max_concurrent_requests",
            ));
        }
        if srv.max_connections == 0
            || srv.max_connections_per_ip == 0
            || srv.max_connections_per_ip > srv.max_connections
        {
            return Err(invalid(
                "require 1 <= server.max_connections_per_ip <= server.max_connections",
            ));
        }
        if !(1..=120).contains(&srv.header_read_timeout_seconds) {
            return Err(invalid(
                "server.header_read_timeout_seconds must be within 1..=120",
            ));
        }

        // --- storage ---
        let st = &self.storage;
        if !st.reject_when_full {
            return Err(invalid(
                "storage.reject_when_full = false is not supported: CipherDrop never evicts live shares",
            ));
        }
        if st.max_memory_mb == 0 || st.max_shares == 0 {
            return Err(invalid(
                "storage.max_memory_mb and storage.max_shares must be > 0",
            ));
        }
        if st.max_memory_mb.saturating_mul(MIB) < self.shares.max_size_bytes.saturating_mul(2) {
            return Err(invalid(
                "storage.max_memory_mb must hold at least two maximum-size shares",
            ));
        }
        if st.persistent_enabled && st.sqlite_path.is_none() {
            return Err(invalid(
                "storage.persistent_enabled requires storage.sqlite_path",
            ));
        }
        if st.default_backend == Backend::Persistent && !st.persistent_enabled {
            return Err(invalid(
                "storage.default_backend = \"persistent\" requires storage.persistent_enabled",
            ));
        }
        if !(1..=3600).contains(&st.cleanup_interval_seconds) {
            return Err(invalid(
                "storage.cleanup_interval_seconds must be within 1..=3600",
            ));
        }

        // --- share limits ---
        let sh = &self.shares;
        if !(1024..=64 * MIB).contains(&sh.max_size_bytes) {
            return Err(invalid(
                "shares.max_size_bytes must be within 1 KiB..=64 MiB",
            ));
        }
        if !(sh.min_ttl_seconds >= 1
            && sh.min_ttl_seconds <= sh.default_ttl_seconds
            && sh.default_ttl_seconds <= sh.max_ttl_seconds
            && sh.max_ttl_seconds <= 366 * 24 * 3600)
        {
            return Err(invalid(
                "require 1 <= min_ttl_seconds <= default_ttl_seconds <= max_ttl_seconds <= 366 days",
            ));
        }
        if !(1..=1000).contains(&sh.max_access_failures) {
            return Err(invalid(
                "shares.max_access_failures must be within 1..=1000",
            ));
        }
        if !(sh.default_max_reads >= 1
            && sh.default_max_reads <= sh.max_reads
            && sh.max_reads <= 1_000_000)
        {
            return Err(invalid(
                "require 1 <= default_max_reads <= max_reads <= 1000000",
            ));
        }

        // --- auth ---
        let mut ids = std::collections::HashSet::new();
        for t in &self.auth.tokens {
            if t.id.len() != 12
                || !t
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(invalid(format!(
                    "auth.tokens: id {:?} must be 12 lowercase hex characters",
                    t.id
                )));
            }
            if !ids.insert(t.id.clone()) {
                return Err(invalid(format!("auth.tokens: duplicate id {}", t.id)));
            }
            if t.sha256.len() != 64 || hex::decode(&t.sha256).is_err() {
                return Err(invalid(format!(
                    "auth.tokens[{}]: sha256 must be 64 hex characters",
                    t.id
                )));
            }
            if t.scopes.is_empty() {
                return Err(invalid(format!(
                    "auth.tokens[{}]: at least one scope is required",
                    t.id
                )));
            }
            for s in &t.scopes {
                if Scope::parse(s).is_none() {
                    return Err(invalid(format!(
                        "auth.tokens[{}]: unknown scope {s:?}",
                        t.id
                    )));
                }
            }
            if let Some(e) = &t.expires_at {
                parse_rfc3339(e)
                    .ok_or_else(|| invalid(format!("auth.tokens[{}]: invalid expires_at", t.id)))?;
            }
        }

        // --- misc ---
        for o in &self.cors.allowed_origins {
            let u = url::Url::parse(o)
                .map_err(|_| invalid(format!("cors.allowed_origins: invalid origin {o:?}")))?;
            if u.origin().ascii_serialization() != *o {
                return Err(invalid(format!(
                    "cors.allowed_origins: {o:?} must be an exact origin like https://app.example.com (no path, no wildcard)"
                )));
            }
        }
        if !["error", "warn", "info", "debug", "trace"].contains(&self.logging.level.as_str()) {
            return Err(invalid(
                "logging.level must be one of error, warn, info, debug, trace",
            ));
        }
        if self.rate_limit.enabled
            && (self.rate_limit.create_per_minute == 0
                || self.rate_limit.read_per_minute == 0
                || self.rate_limit.token_default_per_minute == 0)
        {
            return Err(invalid("rate limits must be > 0 when rate_limit.enabled"));
        }
        if self.rate_limit.ipv6_prefix_len > 128 {
            return Err(invalid("rate_limit.ipv6_prefix_len must be <= 128"));
        }
        Ok(())
    }

    /// Public base URL without trailing slash.
    #[must_use]
    pub fn public_base(&self) -> &str {
        self.server.public_url.trim_end_matches('/')
    }

    /// Origin (`scheme://host[:port]`) of the public URL.
    #[must_use]
    pub fn public_origin(&self) -> String {
        url::Url::parse(&self.server.public_url)
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_default()
    }
}

/// Interpret an environment value as TOML if possible (bool, int, array,
/// inline table), otherwise as a plain string.
fn parse_env_value(v: &str) -> toml::Value {
    #[derive(Deserialize)]
    struct W {
        v: toml::Value,
    }
    match toml::from_str::<W>(&format!("v = {v}")) {
        Ok(w) => w.v,
        Err(_) => toml::Value::String(v.to_owned()),
    }
}

/// Parse an RFC 3339 timestamp to Unix seconds.
#[must_use]
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    u64::try_from(t.unix_timestamp()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> String {
        "[server]\npublic_url = \"https://paste.example.com\"\n".into()
    }

    #[test]
    fn defaults_are_secure_and_valid() {
        let c = Config::from_toml_with_env(&base(), Vec::new()).unwrap();
        c.validate().unwrap();
        assert!(c.security.require_https);
        assert!(!c.storage.persistent_enabled);
        assert!(!c.auth.anonymous_creation);
        assert!(c.server.listen.ip().is_loopback());
        assert!(!c.metrics.enabled);
        assert!(c.cors.allowed_origins.is_empty());
    }

    #[test]
    fn env_overrides() {
        let env = vec![
            (
                "CIPHERDROP__STORAGE__MAX_SHARES".to_string(),
                "42".to_string(),
            ),
            ("CIPHERDROP__AUTH__ANONYMOUS_CREATION".into(), "true".into()),
            (
                "CIPHERDROP__SERVER__PUBLIC_URL".into(),
                "https://other.example".into(),
            ),
            (
                "CIPHERDROP__SECURITY__TRUSTED_PROXIES".into(),
                "[\"10.0.0.0/8\"]".into(),
            ),
            ("UNRELATED".into(), "x".into()),
        ];
        let c = Config::from_toml_with_env(&base(), env).unwrap();
        assert_eq!(c.storage.max_shares, 42);
        assert!(c.auth.anonymous_creation);
        assert_eq!(c.server.public_url, "https://other.example");
        assert_eq!(c.security.trusted_proxies.len(), 1);
    }

    #[test]
    fn unknown_keys_rejected() {
        assert!(Config::from_toml_with_env("[server]\npublik_url = \"x\"", Vec::new()).is_err());
        assert!(
            Config::from_toml_with_env(
                &base(),
                vec![("CIPHERDROP__SERVER__NOPE".into(), "1".into())]
            )
            .is_err()
        );
    }

    fn check(extra: &str) -> Result<(), ConfigError> {
        Config::from_toml_with_env(&format!("{}{extra}", base()), Vec::new())
            .unwrap()
            .validate()
    }

    #[test]
    fn unsafe_settings_rejected() {
        assert!(
            Config::from_toml_with_env("", Vec::new())
                .unwrap()
                .validate()
                .is_err(),
            "public_url required"
        );
        // HTTPS required but http public URL
        assert!(
            Config::from_toml_with_env("[server]\npublic_url=\"http://x.example\"", Vec::new())
                .unwrap()
                .validate()
                .is_err()
        );
        // plain listener on 0.0.0.0 with require_https and no proxy/tls
        assert!(
            Config::from_toml_with_env(
                "[server]\npublic_url=\"https://x.example\"\nlisten=\"0.0.0.0:8080\"",
                Vec::new()
            )
            .unwrap()
            .validate()
            .is_err()
        );
        assert!(check("[storage]\npersistent_enabled = true\n").is_err());
        assert!(check("[storage]\nreject_when_full = false\n").is_err());
        assert!(check("[security]\ntrust_forwarded_headers = true\n").is_err());
        assert!(check("[shares]\ndefault_ttl_seconds = 10\nmin_ttl_seconds = 60\n").is_err());
        assert!(check("[shares]\nmax_reads = 0\n").is_err());
        assert!(check("[cors]\nallowed_origins = [\"*\"]\n").is_err());
        assert!(check("[cors]\nallowed_origins = [\"https://a.example/path\"]\n").is_err());
        assert!(check("[[auth.tokens]]\nid=\"abc\"\nname=\"x\"\nsha256=\"00\"\nscopes=[\"shares:create\"]\n").is_err());
        assert!(check(&format!(
            "[[auth.tokens]]\nid=\"0123456789ab\"\nname=\"x\"\nsha256=\"{}\"\nscopes=[\"root\"]\n",
            "0".repeat(64)
        ))
        .is_err());
    }

    #[test]
    fn proxy_mode_is_valid() {
        let c = Config::from_toml_with_env(
            "[server]\npublic_url=\"https://x.example\"\nlisten=\"0.0.0.0:8080\"\n[security]\ntrust_forwarded_headers=true\ntrusted_proxies=[\"172.16.0.0/12\"]",
            Vec::new(),
        )
        .unwrap();
        c.validate().unwrap();
    }
}
