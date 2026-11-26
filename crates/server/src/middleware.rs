//! Edge middleware applied to every request:
//!
//! 1. Concurrency limit (load shedding with `503`, no unbounded queue).
//! 2. Client address / scheme resolution (trusted proxies only).
//! 3. HTTPS enforcement when the scheme is knowable.
//! 4. Origin validation for state-changing requests (CSRF defence).
//! 5. Request timeout.
//! 6. Security headers and a cache policy on every response.
//! 7. Sanitized access logging: method, route *template*, status, latency.
//!    Never URIs, share ids, headers, bodies, tokens or IP addresses.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;
use crate::metrics::Metrics;
use crate::net::resolve_client;
use crate::state::AppState;

/// CSP for API and other non-HTML responses.
pub const API_CSP: &str =
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

/// CSP for the Swagger UI explorer page (no WebAssembly needed there).
pub const EXPLORER_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// CSP for the single-page application.
///
/// `'wasm-unsafe-eval'` is required to instantiate the bundled Argon2id
/// WebAssembly module; it does not permit JavaScript `eval`.
pub const HTML_CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; \
form-action 'none'; frame-ancestors 'none'";

const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), browsing-topics=(), camera=(), \
display-capture=(), geolocation=(), gyroscope=(), hid=(), interest-cohort=(), magnetometer=(), \
microphone=(), midi=(), payment=(), serial=(), usb=(), clipboard-write=(self)";

fn is_probe(path: &str) -> bool {
    matches!(path, "/healthz" | "/readyz")
}

/// Reject state-changing browser requests from foreign origins.
fn origin_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    if let Some(origin) = headers.get(header::ORIGIN) {
        let Ok(o) = origin.to_str() else { return false };
        return o == state.public_origin || state.cors_origins.contains(o);
    }
    // No Origin header: browsers always send Origin on cross-site POST/DELETE,
    // so its absence indicates a non-browser client (or same-origin legacy UA).
    // Fetch metadata adds defence in depth for user agents that send it.
    !headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("cross-site"))
}

pub async fn edge(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let start = Instant::now();
    let Ok(permit) = state.concurrency.clone().try_acquire_owned() else {
        Metrics::inc(&state.metrics.overloaded);
        let mut r = ApiError::Overloaded.into_response();
        apply_security_headers(&state, r.headers_mut());
        return r;
    };

    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)), |c| c.0);
    let client = resolve_client(
        peer,
        req.headers(),
        &state.config.security,
        state.native_tls,
    );
    req.extensions_mut().insert(client);

    // Per-client in-flight cap: one client cannot hold every global slot
    // (e.g. with deliberately slow uploads).
    let ip_key = crate::net::rate_key(client.ip, state.config.rate_limit.ipv6_prefix_len);
    {
        let mut m = state.inflight_per_ip.lock();
        let n = m.entry(ip_key).or_insert(0);
        if *n >= state.config.server.max_concurrent_requests_per_ip {
            drop(m);
            drop(permit);
            Metrics::inc(&state.metrics.rate_limited);
            let mut r = ApiError::RateLimited {
                retry_after_secs: 1,
            }
            .into_response();
            apply_security_headers(&state, r.headers_mut());
            return r;
        }
        *n += 1;
    }
    let inflight = InflightGuard(&state, ip_key);

    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "<unmatched>".to_owned(), |m| m.as_str().to_owned());
    let path_is_probe = is_probe(req.uri().path());

    let sec = &state.config.security;
    let scheme_knowable = state.native_tls || sec.trust_forwarded_headers;
    let early: Option<ApiError> =
        if sec.require_https && scheme_knowable && !client.https && !path_is_probe {
            Some(ApiError::HttpsRequired)
        } else if !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS)
            && !origin_allowed(&state, req.headers())
        {
            Some(ApiError::CrossOrigin)
        } else {
            None
        };

    let mut res = match early {
        Some(e) => e.into_response(),
        None => {
            let timeout = Duration::from_secs(state.config.security.request_timeout_seconds);
            match tokio::time::timeout(timeout, next.run(req)).await {
                Ok(r) => r,
                Err(_) => ApiError::Timeout.into_response(),
            }
        }
    };
    drop(inflight);
    drop(permit);

    apply_security_headers(&state, res.headers_mut());
    let status = res.status().as_u16();
    state.metrics.record_status(status);
    let latency_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    if status >= 500 {
        tracing::warn!(%method, route, status, latency_ms, "request failed");
    } else {
        tracing::info!(%method, route, status, latency_ms, "request");
    }
    res
}

struct InflightGuard<'a>(&'a AppState, std::net::IpAddr);

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        let mut m = self.0.inflight_per_ip.lock();
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

fn apply_security_headers(state: &AppState, h: &mut HeaderMap) {
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(
        "permissions-policy",
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "x-robots-tag",
        HeaderValue::from_static("noindex, nofollow, noarchive, nosnippet, noimageindex"),
    );
    if state.config.security.require_https {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
    }
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(API_CSP),
        );
    }
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}
