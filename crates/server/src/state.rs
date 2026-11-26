//! Shared application state.

use std::collections::HashSet;
use std::sync::Arc;

use cipherdrop_protocol::api::Scope;
use cipherdrop_storage::memory::{MemoryLimits, MemoryStore};
#[cfg(feature = "sqlite")]
use cipherdrop_storage::sqlite::{PersistentLimits, PersistentStore};
use tokio::sync::Semaphore;

use crate::auth::{TokenRegistry, TokenSource, TokenSpec};
use crate::config::{Config, MIB};
use crate::idempotency::IdempotencyCache;
use crate::metrics::{Gauges, Metrics};
use crate::net::IpLimiters;

#[derive(Clone, Debug)]
pub struct AppState(pub Arc<Inner>);

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

#[derive(Debug)]
pub struct Inner {
    pub config: Config,
    pub memory: MemoryStore,
    #[cfg(feature = "sqlite")]
    pub sqlite: Option<Arc<PersistentStore>>,
    pub tokens: TokenRegistry,
    pub limiters: IpLimiters,
    pub idempotency: IdempotencyCache,
    pub metrics: Metrics,
    pub native_tls: bool,
    pub public_origin: String,
    pub cors_origins: HashSet<String>,
    pub concurrency: Arc<Semaphore>,
    /// In-flight requests per client IP (bounded by `max_concurrent_requests_per_ip`).
    pub inflight_per_ip: parking_lot::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>,
    pub openapi_json: String,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("cannot open the SQLite database")]
    Sqlite,
    #[error("SQLite support is not compiled into this binary")]
    NoSqlite,
}

impl AppState {
    /// Build state from a **validated** configuration.
    ///
    /// # Errors
    /// Fails if the SQLite database cannot be opened.
    pub fn new(config: Config) -> Result<Self, StateError> {
        let max_bytes =
            usize::try_from(config.storage.max_memory_mb.saturating_mul(MIB)).unwrap_or(usize::MAX);
        let memory = MemoryStore::new(MemoryLimits {
            max_bytes,
            max_shares: config.storage.max_shares,
        });
        let tokens = TokenRegistry::new(config.rate_limit.token_default_per_minute);
        tokens.load_static(&config.auth.tokens);

        #[cfg(feature = "sqlite")]
        let sqlite = match &config.storage.sqlite_path {
            None => None,
            Some(p) => {
                let s = PersistentStore::open(
                    p,
                    PersistentLimits {
                        max_bytes: config.storage.persistent_max_mb.saturating_mul(MIB),
                        max_shares: config.storage.persistent_max_shares,
                    },
                )
                .map_err(|_| StateError::Sqlite)?;
                for t in s.list_tokens().map_err(|_| StateError::Sqlite)? {
                    tokens.insert(TokenSpec {
                        id: t.id,
                        name: t.name,
                        verifier: t.verifier,
                        scopes: t.scopes.iter().filter_map(|x| Scope::parse(x)).collect(),
                        created_at: t.created_at,
                        expires_at: t.expires_at,
                        rate_limit_per_minute: t.rate_limit_per_minute,
                        daily_create_quota: t.daily_create_quota,
                        source: TokenSource::Api,
                    });
                }
                Some(Arc::new(s))
            }
        };
        #[cfg(not(feature = "sqlite"))]
        if config.storage.sqlite_path.is_some() {
            return Err(StateError::NoSqlite);
        }

        let rl = &config.rate_limit;
        let limiters =
            IpLimiters::new(rl.create_per_minute, rl.read_per_minute, rl.ipv6_prefix_len);
        let idempotency =
            IdempotencyCache::new(rl.idempotency_ttl_seconds, rl.idempotency_max_entries);
        let native_tls = config.server.tls.is_some();
        let public_origin = config.public_origin();
        let cors_origins = config.cors.allowed_origins.iter().cloned().collect();
        let concurrency = Arc::new(Semaphore::new(config.server.max_concurrent_requests));
        let openapi_json = crate::openapi::render(config.public_base());
        Ok(Self(Arc::new(Inner {
            config,
            memory,
            #[cfg(feature = "sqlite")]
            sqlite,
            tokens,
            limiters,
            idempotency,
            metrics: Metrics::default(),
            native_tls,
            public_origin,
            cors_origins,
            concurrency,
            inflight_per_ip: parking_lot::Mutex::new(std::collections::HashMap::new()),
            openapi_json,
        })))
    }

    /// The persistent share store, if persistent shares are enabled.
    #[cfg(feature = "sqlite")]
    #[must_use]
    pub fn persistent_shares(&self) -> Option<&Arc<PersistentStore>> {
        if self.config.storage.persistent_enabled {
            self.sqlite.as_ref()
        } else {
            None
        }
    }

    #[must_use]
    pub fn gauges(&self) -> Gauges {
        let u = self.memory.usage();
        let l = self.memory.limits();
        #[allow(unused_mut)]
        let mut g = Gauges {
            memory_shares: u.shares as u64,
            memory_bytes: u.bytes as u64,
            memory_budget_bytes: l.max_bytes as u64,
            memory_max_shares: l.max_shares as u64,
            persistent_shares: None,
            persistent_bytes: None,
        };
        #[cfg(feature = "sqlite")]
        if let Some(s) = self.persistent_shares()
            && let Ok((n, b)) = s.usage()
        {
            g.persistent_shares = Some(n);
            g.persistent_bytes = Some(b);
        }
        g
    }
}
