//! Administrative API token management (`admin:manage`).
//!
//! Administrators manage credentials and may revoke shares; they can never
//! decrypt shares, because the server never holds content keys.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use cipherdrop_protocol::api::{
    CreateTokenRequest, CreateTokenResponse, Problem, Scope, TokenInfo,
};

use crate::auth::{TokenSource, TokenSpec, generate_token};
use crate::error::ApiError;
use crate::extract::{Principal, StrictJson};
use crate::state::AppState;
use crate::util::now_unix;

fn no_store(mut r: Response) -> Response {
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// Create an API token. The secret is returned exactly once.
#[utoipa::path(
    post,
    path = "/api/v1/admin/tokens",
    tag = "admin",
    request_body(content = CreateTokenRequest, content_type = "application/json"),
    responses(
        (status = 201, description = "Token created; store the secret now", body = CreateTokenResponse),
        (status = 400, description = "Invalid request", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Requires admin:manage", body = Problem, content_type = "application/problem+json"),
    ),
    security(("bearer" = []))
)]
pub async fn create_token(
    State(state): State<AppState>,
    principal: Principal,
    body: StrictJson<CreateTokenRequest>,
) -> Result<Response, ApiError> {
    principal.require(Scope::AdminManage)?;
    let req = body.value;
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
        return Err(ApiError::InvalidRequest(
            "name must be 1..=64 printable characters",
        ));
    }
    if req.scopes.is_empty() {
        return Err(ApiError::InvalidRequest("At least one scope is required"));
    }
    if req.rate_limit_per_minute == Some(0) {
        return Err(ApiError::InvalidRequest(
            "rate_limit_per_minute must be > 0",
        ));
    }
    let now = now_unix();
    let expires_at = match req.expires_in_seconds {
        None => None,
        Some(s) if (60..=10 * 366 * 86_400).contains(&s) => Some(now + s),
        Some(_) => {
            return Err(ApiError::InvalidRequest(
                "expires_in_seconds must be within 60 seconds..10 years",
            ));
        }
    };
    let g = generate_token()?;
    let spec = TokenSpec {
        id: g.id.clone(),
        name: name.to_owned(),
        verifier: g.verifier,
        scopes: req.scopes.iter().copied().collect(),
        created_at: now,
        expires_at,
        rate_limit_per_minute: req.rate_limit_per_minute,
        daily_create_quota: req.daily_create_quota,
        source: TokenSource::Api,
    };
    #[cfg(feature = "sqlite")]
    if let Some(db) = state.sqlite.clone() {
        let rec = cipherdrop_storage::sqlite::StoredToken {
            id: spec.id.clone(),
            name: spec.name.clone(),
            verifier: spec.verifier,
            scopes: spec.scopes.iter().map(|s| s.as_str().to_owned()).collect(),
            created_at: now,
            expires_at,
            rate_limit_per_minute: spec.rate_limit_per_minute,
            daily_create_quota: spec.daily_create_quota,
        };
        tokio::task::spawn_blocking(move || db.insert_token(&rec))
            .await
            .map_err(|_| ApiError::Internal)?
            .map_err(|_| ApiError::Internal)?;
    }
    state.tokens.insert(spec);
    let info = state.tokens.get(&g.id).ok_or(ApiError::Internal)?.info();
    tracing::info!(token_id = %info.id, "api token created");
    Ok(no_store(
        (
            StatusCode::CREATED,
            Json(CreateTokenResponse {
                token: g.token.to_string(),
                info,
            }),
        )
            .into_response(),
    ))
}

/// List API tokens (metadata only; secrets are never retrievable).
#[utoipa::path(
    get,
    path = "/api/v1/admin/tokens",
    tag = "admin",
    responses(
        (status = 200, description = "Active tokens", body = Vec<TokenInfo>),
        (status = 401, description = "Authentication required", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Requires admin:manage", body = Problem, content_type = "application/problem+json"),
    ),
    security(("bearer" = []))
)]
pub async fn list_tokens(
    State(state): State<AppState>,
    principal: Principal,
) -> Result<Response, ApiError> {
    principal.require(Scope::AdminManage)?;
    let list: Vec<TokenInfo> = state.tokens.list().iter().map(|t| t.info()).collect();
    Ok(no_store(Json(list).into_response()))
}

/// Revoke an API token created through the admin API.
///
/// Tokens declared in the configuration file must be removed there.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/tokens/{id}",
    tag = "admin",
    params(("id" = String, Path, description = "Token id (12 hex characters)")),
    responses(
        (status = 204, description = "Token revoked"),
        (status = 403, description = "Requires admin:manage, or token is defined in the configuration file", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown token", body = Problem, content_type = "application/problem+json"),
    ),
    security(("bearer" = []))
)]
pub async fn revoke_token(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    principal.require(Scope::AdminManage)?;
    let rec = state.tokens.get(&id).ok_or(ApiError::NotFound)?;
    if rec.source == TokenSource::Config {
        return Err(ApiError::Forbidden(
            "Tokens defined in the configuration file must be removed there",
        ));
    }
    #[cfg(feature = "sqlite")]
    if let Some(db) = state.sqlite.clone() {
        let id2 = id.clone();
        tokio::task::spawn_blocking(move || db.revoke_token(&id2, now_unix()))
            .await
            .map_err(|_| ApiError::Internal)?
            .map_err(|_| ApiError::Internal)?;
    }
    state.tokens.remove(&id);
    tracing::info!(token_id = %id, "api token revoked");
    Ok(no_store(StatusCode::NO_CONTENT.into_response()))
}
