//! Request extractors: authenticated principal, strict JSON bodies, client info.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::header;
use axum::http::request::Parts;
use cipherdrop_protocol::api::Scope;
use serde::de::DeserializeOwned;

use crate::auth::TokenRecord;
use crate::error::ApiError;
use crate::metrics::Metrics;
use crate::net::ClientInfo;
use crate::state::AppState;
use crate::util::now_unix;

/// Who is making the request.
#[derive(Debug, Clone)]
pub enum Principal {
    Anonymous,
    Token(Arc<TokenRecord>),
}

impl Principal {
    /// Require a scope.
    ///
    /// # Errors
    /// `401` for anonymous callers, `403 insufficient_scope` for tokens lacking `scope`.
    pub fn require(&self, scope: Scope) -> Result<&Arc<TokenRecord>, ApiError> {
        match self {
            Self::Anonymous => Err(ApiError::Unauthorized),
            Self::Token(t) if t.has(scope) => Ok(t),
            Self::Token(_) => Err(ApiError::InsufficientScope(scope_detail(scope))),
        }
    }

    #[must_use]
    pub fn has(&self, scope: Scope) -> bool {
        matches!(self, Self::Token(t) if t.has(scope))
    }

    /// Stable string identifying the principal (for idempotency scoping).
    #[must_use]
    pub fn key(&self, client: &ClientInfo) -> String {
        match self {
            Self::Anonymous => format!("anon:{}", client.ip),
            Self::Token(t) => format!("token:{}", t.id),
        }
    }
}

const fn scope_detail(s: Scope) -> &'static str {
    match s {
        Scope::SharesCreate => "Requires scope shares:create",
        Scope::SharesCreatePersistent => "Requires scope shares:create:persistent",
        Scope::SharesConsume => "Requires scope shares:consume",
        Scope::SharesRevoke => "Requires scope shares:revoke",
        Scope::AdminMetrics => "Requires scope admin:metrics",
        Scope::AdminManage => "Requires scope admin:manage",
    }
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let Some(v) = parts.headers.get(header::AUTHORIZATION) else {
            return Ok(Self::Anonymous);
        };
        // A present but invalid credential is an error, never a silent downgrade.
        let v = v.to_str().map_err(|_| ApiError::Unauthorized)?;
        let rec = state.tokens.authenticate(v, now_unix()).inspect_err(|_| {
            Metrics::inc(&state.metrics.auth_failures);
        })?;
        if state.config.rate_limit.enabled {
            rec.check_rate()
                .inspect_err(|_| Metrics::inc(&state.metrics.rate_limited))?;
        }
        Ok(Self::Token(rec))
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientInfo {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, ApiError> {
        parts
            .extensions
            .get::<Self>()
            .copied()
            .ok_or(ApiError::Internal)
    }
}

/// Strict JSON body: requires `Content-Type: application/json`, rejects
/// malformed bodies with a generic `400` (no echo of the input), and keeps the
/// raw bytes for idempotency hashing.
#[derive(Debug)]
pub struct StrictJson<T> {
    pub value: T,
    pub raw: Bytes,
}

pub fn is_json_content_type(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
}

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for StrictJson<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        if !is_json_content_type(req.headers()) {
            return Err(ApiError::UnsupportedMediaType);
        }
        let raw = Bytes::from_request(req, state).await.map_err(|e| {
            if e.status() == axum::http::StatusCode::PAYLOAD_TOO_LARGE {
                ApiError::PayloadTooLarge
            } else {
                ApiError::InvalidRequest("Could not read request body")
            }
        })?;
        let value = serde_json::from_slice(&raw).map_err(|_| {
            ApiError::InvalidRequest("Request body does not match the expected JSON schema")
        })?;
        Ok(Self { value, raw })
    }
}
