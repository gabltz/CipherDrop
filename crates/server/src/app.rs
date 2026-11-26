//! Router assembly.

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, HeaderValue, Method, header};
use axum::routing::{delete, get, post};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::error::ApiError;
use crate::middleware;
use crate::routes::{admin, meta, shares};
use crate::state::AppState;
use crate::static_files;

/// Maximum accepted request body: base64 expansion of the largest allowed
/// ciphertext plus room for JSON framing and KDF parameters.
#[must_use]
pub fn body_limit(max_ciphertext: u64) -> usize {
    let b64 = max_ciphertext.div_ceil(3) * 4;
    usize::try_from(b64 + 8 * 1024).unwrap_or(usize::MAX)
}

pub fn build_router(state: AppState) -> Router {
    let mut api = Router::new()
        .route("/shares", post(shares::create_share))
        .route("/shares/{id}", delete(shares::revoke_share))
        .route("/shares/{id}/consume", post(shares::consume_share))
        .route("/shares/{id}/status", get(shares::share_status))
        .route("/config", get(meta::get_config))
        .route("/version", get(meta::get_version))
        .route("/openapi.json", get(meta::get_openapi))
        .route(
            "/admin/tokens",
            post(admin::create_token).get(admin::list_tokens),
        )
        .route("/admin/tokens/{id}", delete(admin::revoke_token))
        .fallback(|| async { ApiError::NotFound });

    if !state.cors_origins.is_empty() {
        let origins: Vec<HeaderValue> = state
            .cors_origins
            .iter()
            .filter_map(|o| HeaderValue::from_str(o).ok())
            .collect();
        api = api.layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([Method::GET, Method::POST, Method::DELETE])
                .allow_headers([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    HeaderName::from_static("idempotency-key"),
                    HeaderName::from_static(shares::REVOCATION_HEADER),
                ])
                .max_age(std::time::Duration::from_secs(600)),
        );
    }

    Router::new()
        .nest("/api/v1", api)
        .route("/healthz", get(meta::healthz))
        .route("/readyz", get(meta::readyz))
        .route("/metrics", get(meta::metrics))
        .route("/", get(static_files::spa))
        .route("/s/{id}", get(static_files::spa))
        .route("/revoke/{id}", get(static_files::spa))
        .route("/docs", get(static_files::spa))
        .route("/docs/api/explorer", get(static_files::api_explorer))
        .route("/docs/{*page}", get(static_files::spa))
        .route("/assets/{*path}", get(static_files::asset))
        .route("/swagger/{*path}", get(static_files::swagger_asset))
        .route("/favicon.svg", get(static_files::favicon))
        .route("/robots.txt", get(static_files::robots))
        .fallback(|| async { ApiError::NotFound })
        .layer(DefaultBodyLimit::max(body_limit(
            state.config.shares.max_size_bytes,
        )))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::edge,
        ))
        .with_state(state)
}
