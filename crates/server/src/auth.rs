//! Scoped API tokens.
//!
//! Token format: `cdt_{id}_{secret}`
//! * `id`: 12 lowercase hex characters (48 random bits), public, used for lookup.
//! * `secret`: 43 base64url characters (256 random bits).
//!
//! The server stores only `SHA-256(token)` (a fast hash is sufficient for a
//! 256-bit random secret) and compares in constant time. Tokens come from the
//! configuration file (immutable) or from the admin API (persisted in SQLite
//! when `storage.sqlite_path` is configured, otherwise kept in RAM only).

use std::collections::{BTreeSet, HashMap};
use std::num::NonZeroU32;
use std::sync::Arc;

use cipherdrop_protocol::api::{Scope, TokenInfo};
use cipherdrop_storage::Verifier;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use parking_lot::{Mutex, RwLock};
use zeroize::Zeroizing;

use crate::config::{StaticToken, parse_rfc3339};
use crate::error::ApiError;
use crate::util::{random_b64, rfc3339};

pub const TOKEN_PREFIX: &str = "cdt_";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    Config,
    Api,
}

pub struct TokenRecord {
    pub id: String,
    pub name: String,
    verifier: Verifier,
    pub scopes: BTreeSet<Scope>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub rate_limit_per_minute: Option<u32>,
    pub daily_create_quota: Option<u32>,
    pub source: TokenSource,
    limiter: DefaultDirectRateLimiter,
    /// `(utc_day, creations)`; resets on a new UTC day and on restart.
    quota_used: Mutex<(u64, u32)>,
}

impl core::fmt::Debug for TokenRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TokenRecord")
            .field("id", &self.id)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

impl TokenRecord {
    #[must_use]
    pub fn has(&self, s: Scope) -> bool {
        self.scopes.contains(&s)
    }

    /// Per-token rate limit check.
    ///
    /// # Errors
    /// [`ApiError::RateLimited`] when the token exceeded its rate.
    pub fn check_rate(&self) -> Result<(), ApiError> {
        self.limiter.check().map_err(|_| ApiError::RateLimited {
            retry_after_secs: 60,
        })
    }

    /// Count one share creation against the daily quota.
    ///
    /// # Errors
    /// [`ApiError::QuotaExceeded`] when the quota is used up.
    pub fn charge_create(&self, now: u64) -> Result<(), ApiError> {
        let Some(limit) = self.daily_create_quota else {
            return Ok(());
        };
        let day = now / 86_400;
        let mut q = self.quota_used.lock();
        if q.0 != day {
            *q = (day, 0);
        }
        if q.1 >= limit {
            return Err(ApiError::QuotaExceeded);
        }
        q.1 += 1;
        Ok(())
    }

    #[must_use]
    pub fn info(&self) -> TokenInfo {
        TokenInfo {
            id: self.id.clone(),
            name: self.name.clone(),
            scopes: self.scopes.iter().copied().collect(),
            created_at: rfc3339(self.created_at),
            expires_at: self.expires_at.map(rfc3339),
            rate_limit_per_minute: self.rate_limit_per_minute,
            daily_create_quota: self.daily_create_quota,
            source: match self.source {
                TokenSource::Config => "config".into(),
                TokenSource::Api => "api".into(),
            },
        }
    }

    #[must_use]
    pub fn verifier(&self) -> Verifier {
        self.verifier
    }
}

/// Parameters for building a token record.
#[derive(Debug, Clone)]
pub struct TokenSpec {
    pub id: String,
    pub name: String,
    pub verifier: Verifier,
    pub scopes: BTreeSet<Scope>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub rate_limit_per_minute: Option<u32>,
    pub daily_create_quota: Option<u32>,
    pub source: TokenSource,
}

/// In-memory index of all active tokens.
#[derive(Debug)]
pub struct TokenRegistry {
    tokens: RwLock<HashMap<String, Arc<TokenRecord>>>,
    default_rpm: u32,
}

/// A freshly generated token. The secret string is shown to the operator once.
pub struct GeneratedToken {
    pub token: Zeroizing<String>,
    pub id: String,
    pub verifier: Verifier,
}

impl core::fmt::Debug for GeneratedToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GeneratedToken")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Generate a new random token.
///
/// # Errors
/// [`ApiError::Internal`] if the OS RNG fails.
pub fn generate_token() -> Result<GeneratedToken, ApiError> {
    let mut idb = [0u8; 6];
    getrandom::fill(&mut idb).map_err(|_| ApiError::Internal)?;
    let id = hex::encode(idb);
    let secret = Zeroizing::new(random_b64::<32>()?);
    let token = Zeroizing::new(format!("{TOKEN_PREFIX}{id}_{}", secret.as_str()));
    let verifier = Verifier::from_secret(token.as_bytes());
    Ok(GeneratedToken {
        token,
        id,
        verifier,
    })
}

impl TokenRegistry {
    #[must_use]
    pub fn new(default_rpm: u32) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            default_rpm: default_rpm.max(1),
        }
    }

    pub fn insert(&self, spec: TokenSpec) {
        let rpm = NonZeroU32::new(spec.rate_limit_per_minute.unwrap_or(self.default_rpm))
            .unwrap_or(NonZeroU32::MIN);
        let rec = TokenRecord {
            limiter: RateLimiter::direct(Quota::per_minute(rpm)),
            quota_used: Mutex::new((0, 0)),
            id: spec.id.clone(),
            name: spec.name,
            verifier: spec.verifier,
            scopes: spec.scopes,
            created_at: spec.created_at,
            expires_at: spec.expires_at,
            rate_limit_per_minute: spec.rate_limit_per_minute,
            daily_create_quota: spec.daily_create_quota,
            source: spec.source,
        };
        self.tokens.write().insert(spec.id, Arc::new(rec));
    }

    /// Load static tokens from configuration (already validated).
    pub fn load_static(&self, tokens: &[StaticToken]) {
        for t in tokens {
            let mut v = [0u8; 32];
            if hex::decode_to_slice(&t.sha256, &mut v).is_err() {
                continue;
            }
            self.insert(TokenSpec {
                id: t.id.clone(),
                name: t.name.clone(),
                verifier: Verifier(v),
                scopes: t.scopes.iter().filter_map(|s| Scope::parse(s)).collect(),
                created_at: 0,
                expires_at: t.expires_at.as_deref().and_then(parse_rfc3339),
                rate_limit_per_minute: t.rate_limit_per_minute,
                daily_create_quota: t.daily_create_quota,
                source: TokenSource::Config,
            });
        }
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<Arc<TokenRecord>> {
        self.tokens.read().get(id).cloned()
    }

    pub fn remove(&self, id: &str) -> Option<Arc<TokenRecord>> {
        self.tokens.write().remove(id)
    }

    #[must_use]
    pub fn list(&self) -> Vec<Arc<TokenRecord>> {
        let mut v: Vec<_> = self.tokens.read().values().cloned().collect();
        v.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        v
    }

    /// Authenticate an `Authorization` header value.
    ///
    /// # Errors
    /// [`ApiError::Unauthorized`] for malformed, unknown, mismatched or expired tokens.
    pub fn authenticate(&self, header_value: &str, now: u64) -> Result<Arc<TokenRecord>, ApiError> {
        let token = header_value
            .strip_prefix("Bearer ")
            .map(str::trim)
            .ok_or(ApiError::Unauthorized)?;
        let rest = token
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(ApiError::Unauthorized)?;
        let (id, secret) = rest.split_once('_').ok_or(ApiError::Unauthorized)?;
        if id.len() != 12 || secret.len() != 43 {
            return Err(ApiError::Unauthorized);
        }
        let rec = self.get(id).ok_or(ApiError::Unauthorized)?;
        if !rec.verifier.verify(token.as_bytes()) {
            return Err(ApiError::Unauthorized);
        }
        if rec.expires_at.is_some_and(|e| e <= now) {
            return Err(ApiError::Unauthorized);
        }
        Ok(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg_with(scopes: &[Scope], expires_at: Option<u64>) -> (TokenRegistry, String) {
        let r = TokenRegistry::new(600);
        let g = generate_token().unwrap();
        r.insert(TokenSpec {
            id: g.id.clone(),
            name: "t".into(),
            verifier: g.verifier,
            scopes: scopes.iter().copied().collect(),
            created_at: 0,
            expires_at,
            rate_limit_per_minute: Some(2),
            daily_create_quota: Some(1),
            source: TokenSource::Api,
        });
        (r, g.token.to_string())
    }

    #[test]
    fn token_format() {
        let g = generate_token().unwrap();
        assert!(g.token.starts_with("cdt_"));
        assert_eq!(g.token.len(), 4 + 12 + 1 + 43);
    }

    #[test]
    fn authenticate_paths() {
        let (r, tok) = reg_with(&[Scope::SharesCreate], Some(100));
        let rec = r.authenticate(&format!("Bearer {tok}"), 0).unwrap();
        assert!(rec.has(Scope::SharesCreate));
        assert!(!rec.has(Scope::AdminManage));
        assert!(r.authenticate(&tok, 0).is_err(), "missing Bearer");
        assert!(
            r.authenticate(&format!("Bearer {tok}"), 100).is_err(),
            "expired"
        );
        let mut bad = tok.clone();
        bad.pop();
        bad.push(if tok.ends_with('A') { 'B' } else { 'A' });
        assert!(
            r.authenticate(&format!("Bearer {bad}"), 0).is_err(),
            "wrong secret"
        );
        assert!(r.authenticate("Bearer cdt_000000000000_x", 0).is_err());
    }

    #[test]
    fn per_token_rate_limit_and_quota() {
        let (r, tok) = reg_with(&[Scope::SharesCreate], None);
        let rec = r.authenticate(&format!("Bearer {tok}"), 0).unwrap();
        assert!(rec.check_rate().is_ok());
        assert!(rec.check_rate().is_ok());
        assert!(rec.check_rate().is_err());
        assert!(rec.charge_create(10).is_ok());
        assert_eq!(rec.charge_create(20), Err(ApiError::QuotaExceeded));
        assert!(rec.charge_create(86_400 + 1).is_ok(), "new day");
    }
}
