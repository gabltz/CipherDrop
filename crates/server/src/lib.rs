//! CipherDrop server library. The binary in `main.rs` wires configuration,
//! logging, hardening and the listener; integration tests build the router
//! directly from [`app::build_router`].

#![forbid(unsafe_code)]

pub mod app;
pub mod auth;
pub mod config;
pub mod error;
pub mod extract;
pub mod hardening;
pub mod idempotency;
pub mod metrics;
pub mod middleware;
pub mod net;
pub mod openapi;
pub mod routes;
pub mod state;
pub mod static_files;
pub mod util;

use std::time::Duration;

use crate::state::AppState;
use crate::util::now_unix;

/// Periodic maintenance: reclaim expired shares and prune rate-limiter and
/// idempotency state. Runs until the process exits.
pub async fn maintenance_loop(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(
        state.config.storage.cleanup_interval_seconds,
    ));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let now = now_unix();
        let n = state.memory.purge_expired(now);
        #[cfg(feature = "sqlite")]
        let n = n + match state.persistent_shares().cloned() {
            Some(s) => tokio::task::spawn_blocking(move || s.purge_expired(now))
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(0),
            None => 0,
        };
        state
            .metrics
            .expired_reclaimed
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        state.limiters.cleanup();
        state.idempotency.cleanup(now);
    }
}
