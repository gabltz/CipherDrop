//! Prometheus metrics with a fixed, bounded label set.
//!
//! No metric carries share identifiers, tokens, IP addresses or content.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[derive(Debug, Default)]
pub struct Metrics {
    pub created_memory: AtomicU64,
    pub created_persistent: AtomicU64,
    pub consumed_memory: AtomicU64,
    pub consumed_persistent: AtomicU64,
    pub consume_unavailable: AtomicU64,
    pub revoked: AtomicU64,
    pub expired_reclaimed: AtomicU64,
    pub rejected_capacity: AtomicU64,
    pub rate_limited: AtomicU64,
    pub auth_failures: AtomicU64,
    pub overloaded: AtomicU64,
    pub http_2xx: AtomicU64,
    pub http_4xx: AtomicU64,
    pub http_5xx: AtomicU64,
}

/// Gauges sampled at scrape time.
#[derive(Debug, Clone, Copy, Default)]
pub struct Gauges {
    pub memory_shares: u64,
    pub memory_bytes: u64,
    pub memory_budget_bytes: u64,
    pub memory_max_shares: u64,
    pub persistent_shares: Option<u64>,
    pub persistent_bytes: Option<u64>,
}

impl Metrics {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Relaxed);
    }

    pub fn record_status(&self, status: u16) {
        match status {
            200..=399 => Self::inc(&self.http_2xx),
            400..=499 => Self::inc(&self.http_4xx),
            _ => Self::inc(&self.http_5xx),
        }
    }

    #[must_use]
    pub fn render(&self, g: Gauges) -> String {
        let mut s = String::with_capacity(2048);
        let mut counter = |name: &str, help: &str, series: &[(&str, &AtomicU64)]| {
            let _ = writeln!(s, "# HELP {name} {help}\n# TYPE {name} counter");
            for (labels, v) in series {
                let _ = writeln!(s, "{name}{labels} {}", v.load(Relaxed));
            }
        };
        counter(
            "cipherdrop_shares_created_total",
            "Shares created.",
            &[
                ("{storage=\"memory\"}", &self.created_memory),
                ("{storage=\"persistent\"}", &self.created_persistent),
            ],
        );
        counter(
            "cipherdrop_shares_consumed_total",
            "Successful share retrievals.",
            &[
                ("{storage=\"memory\"}", &self.consumed_memory),
                ("{storage=\"persistent\"}", &self.consumed_persistent),
            ],
        );
        counter(
            "cipherdrop_consume_unavailable_total",
            "Retrieval attempts for unavailable shares.",
            &[("", &self.consume_unavailable)],
        );
        counter(
            "cipherdrop_shares_revoked_total",
            "Shares revoked.",
            &[("", &self.revoked)],
        );
        counter(
            "cipherdrop_shares_expired_total",
            "Expired shares reclaimed by the cleaner.",
            &[("", &self.expired_reclaimed)],
        );
        counter(
            "cipherdrop_create_rejected_capacity_total",
            "Creations rejected because storage was full.",
            &[("", &self.rejected_capacity)],
        );
        counter(
            "cipherdrop_rate_limited_total",
            "Requests rejected by rate limiting.",
            &[("", &self.rate_limited)],
        );
        counter(
            "cipherdrop_auth_failures_total",
            "Requests with invalid credentials.",
            &[("", &self.auth_failures)],
        );
        counter(
            "cipherdrop_overloaded_total",
            "Requests shed due to the concurrency limit.",
            &[("", &self.overloaded)],
        );
        counter(
            "cipherdrop_http_responses_total",
            "HTTP responses by status class.",
            &[
                ("{class=\"2xx_3xx\"}", &self.http_2xx),
                ("{class=\"4xx\"}", &self.http_4xx),
                ("{class=\"5xx\"}", &self.http_5xx),
            ],
        );
        let mut gauge = |name: &str, help: &str, v: u64| {
            let _ = writeln!(s, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
        };
        gauge(
            "cipherdrop_memory_shares",
            "Shares held in RAM.",
            g.memory_shares,
        );
        gauge(
            "cipherdrop_memory_bytes",
            "Accounted bytes held in RAM.",
            g.memory_bytes,
        );
        gauge(
            "cipherdrop_memory_budget_bytes",
            "Configured RAM budget.",
            g.memory_budget_bytes,
        );
        gauge(
            "cipherdrop_memory_max_shares",
            "Configured maximum share count.",
            g.memory_max_shares,
        );
        if let (Some(n), Some(b)) = (g.persistent_shares, g.persistent_bytes) {
            gauge("cipherdrop_persistent_shares", "Shares held in SQLite.", n);
            gauge(
                "cipherdrop_persistent_bytes",
                "Ciphertext bytes held in SQLite.",
                b,
            );
        }
        s
    }
}
