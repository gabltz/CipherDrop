//! Instance metadata, health, metrics and OpenAPI endpoints.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use cipherdrop_protocol::api::{ConfigResponse, KdfLimits, Problem, Scope, VersionResponse};

use crate::error::ApiError;
use crate::extract::Principal;
use crate::state::AppState;

/// Public instance capabilities and limits.
#[utoipa::path(
    get,
    path = "/api/v1/config",
    tag = "instance",
    responses((status = 200, description = "Instance capabilities", body = ConfigResponse))
)]
pub async fn get_config(State(state): State<AppState>) -> Json<ConfigResponse> {
    let c = &state.config;
    Json(ConfigResponse {
        public_url: c.public_base().to_owned(),
        protocol_versions: vec![cipherdrop_protocol::PROTOCOL_VERSION],
        max_ciphertext_bytes: c.shares.max_size_bytes,
        default_ttl_seconds: c.shares.default_ttl_seconds,
        max_ttl_seconds: c.shares.max_ttl_seconds,
        default_max_reads: c.shares.default_max_reads,
        max_reads: c.shares.max_reads,
        allow_unlimited_reads: c.shares.allow_unlimited_reads,
        allow_permanent: c.shares.allow_permanent,
        persistent_enabled: c.storage.persistent_enabled,
        anonymous_creation: c.auth.anonymous_creation,
        anonymous_retrieval: c.auth.anonymous_retrieval,
        kdf: KdfLimits::default(),
    })
}

/// Server version and supported protocol versions.
#[utoipa::path(
    get,
    path = "/api/v1/version",
    tag = "instance",
    responses((status = 200, description = "Version information", body = VersionResponse))
)]
pub async fn get_version() -> Json<VersionResponse> {
    Json(VersionResponse {
        name: "CipherDrop".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        api_version: "v1".into(),
        protocol_versions: vec![cipherdrop_protocol::PROTOCOL_VERSION],
        algorithms: vec![cipherdrop_protocol::ALGORITHM_AES_256_GCM.into()],
    })
}

/// The OpenAPI 3.1 document for this instance.
#[utoipa::path(
    get,
    path = "/api/v1/openapi.json",
    tag = "instance",
    responses((status = 200, description = "OpenAPI document", content_type = "application/json"))
)]
pub async fn get_openapi(State(state): State<AppState>) -> Response {
    let mut r = state.openapi_json.clone().into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r
}

/// Liveness probe.
#[utoipa::path(get, path = "/healthz", tag = "operations", responses((status = 200, description = "Process is alive")))]
pub async fn healthz() -> &'static str {
    "ok"
}

/// Readiness probe: verifies storage backends are usable.
#[utoipa::path(
    get,
    path = "/readyz",
    tag = "operations",
    responses((status = 200, description = "Ready"), (status = 503, description = "Not ready"))
)]
pub async fn readyz(State(state): State<AppState>) -> Response {
    #[cfg(feature = "sqlite")]
    if let Some(s) = state.sqlite.clone() {
        let ok = tokio::task::spawn_blocking(move || s.healthy())
            .await
            .unwrap_or(false);
        if !ok {
            return (StatusCode::SERVICE_UNAVAILABLE, "sqlite unavailable").into_response();
        }
    }
    let _ = &state;
    (StatusCode::OK, "ready").into_response()
}

/// Prometheus metrics (requires `admin:metrics` unless configured otherwise).
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "operations",
    responses(
        (status = 200, description = "Prometheus text format", content_type = "text/plain"),
        (status = 401, description = "Authentication required", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Metrics disabled", body = Problem, content_type = "application/problem+json"),
    ),
    security(("bearer" = []))
)]
pub async fn metrics(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Response, ApiError> {
    if !state.config.metrics.enabled {
        return Err(ApiError::NotFound);
    }
    if state.config.metrics.require_token {
        principal.require(Scope::AdminMetrics)?;
    }
    let body = state.metrics.render(state.gauges());
    let mut r = body.into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(r)
}
