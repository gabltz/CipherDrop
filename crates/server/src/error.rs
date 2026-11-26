//! API errors rendered as RFC 9457 Problem Details.
//!
//! Error bodies are static strings: they never echo request content,
//! identifiers, tokens or internal error messages.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use cipherdrop_protocol::api::Problem;

pub const PROBLEM_BASE: &str = "https://cipherdrop.dev/problems/";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    #[error("invalid request")]
    InvalidRequest(&'static str),
    #[error("unsupported media type")]
    UnsupportedMediaType,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("authentication required")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden(&'static str),
    #[error("insufficient scope")]
    InsufficientScope(&'static str),
    #[error("cross-origin request rejected")]
    CrossOrigin,
    #[error("https required")]
    HttpsRequired,
    #[error("share unavailable")]
    ShareUnavailable,
    #[error("access denied")]
    AccessDenied,
    #[error("share destroyed")]
    ShareDestroyed,
    #[error("not found")]
    NotFound,
    #[error("idempotency key conflict")]
    IdempotencyConflict,
    #[error("rate limited")]
    RateLimited { retry_after_secs: u64 },
    #[error("quota exceeded")]
    QuotaExceeded,
    #[error("capacity exhausted")]
    CapacityExhausted,
    #[error("feature disabled")]
    FeatureDisabled(&'static str),
    #[error("server overloaded")]
    Overloaded,
    #[error("request timeout")]
    Timeout,
    #[error("internal error")]
    Internal,
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str, &'static str, Option<&'static str>) {
        use ApiError::*;
        match self {
            InvalidRequest(d) => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid request",
                Some(d),
            ),
            UnsupportedMediaType => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Unsupported media type",
                Some("Requests with a body must use Content-Type: application/json"),
            ),
            PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "Payload too large",
                Some("The encrypted payload exceeds this instance's limit; see GET /api/v1/config"),
            ),
            Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required",
                Some("Provide a valid API token: Authorization: Bearer cdt_..."),
            ),
            Forbidden(d) => (StatusCode::FORBIDDEN, "forbidden", "Forbidden", Some(d)),
            InsufficientScope(d) => (
                StatusCode::FORBIDDEN,
                "insufficient_scope",
                "Insufficient scope",
                Some(d),
            ),
            CrossOrigin => (
                StatusCode::FORBIDDEN,
                "cross_origin_rejected",
                "Cross-origin request rejected",
                Some("This origin is not allowed to call the API"),
            ),
            HttpsRequired => (
                StatusCode::FORBIDDEN,
                "https_required",
                "HTTPS required",
                None,
            ),
            ShareUnavailable => (
                StatusCode::NOT_FOUND,
                "share_unavailable",
                "Share unavailable",
                Some(
                    "The share does not exist, has expired, has already been retrieved the maximum number of times, or was revoked",
                ),
            ),
            AccessDenied => (
                StatusCode::FORBIDDEN,
                "access_denied",
                "Access denied",
                Some(
                    "This share requires its password: missing or wrong access key. Nothing was consumed",
                ),
            ),
            ShareDestroyed => (
                StatusCode::GONE,
                "share_destroyed",
                "Share destroyed",
                Some("Too many wrong password attempts; the share has been deleted"),
            ),
            NotFound => (StatusCode::NOT_FOUND, "not_found", "Not found", None),
            IdempotencyConflict => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "idempotency_key_reused",
                "Idempotency key reused",
                Some("This Idempotency-Key was already used with a different request body"),
            ),
            RateLimited { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many requests",
                None,
            ),
            QuotaExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "quota_exceeded",
                "Quota exceeded",
                Some("This API token has reached its daily share-creation quota"),
            ),
            CapacityExhausted => (
                StatusCode::INSUFFICIENT_STORAGE,
                "capacity_exhausted",
                "Storage capacity exhausted",
                Some("The instance is full. Existing shares are never evicted; retry later"),
            ),
            FeatureDisabled(d) => (
                StatusCode::FORBIDDEN,
                "feature_disabled",
                "Feature disabled",
                Some(d),
            ),
            Overloaded => (
                StatusCode::SERVICE_UNAVAILABLE,
                "overloaded",
                "Server overloaded",
                Some("Too many concurrent requests; retry later"),
            ),
            Timeout => (
                StatusCode::REQUEST_TIMEOUT,
                "timeout",
                "Request timeout",
                None,
            ),
            Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal server error",
                None,
            ),
        }
    }

    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.parts().0
    }

    #[must_use]
    pub fn problem(&self) -> Problem {
        let (status, code, title, detail) = self.parts();
        Problem {
            type_uri: format!("{PROBLEM_BASE}{}", code.replace('_', "-")),
            title: title.to_owned(),
            status: status.as_u16(),
            detail: detail.map(str::to_owned),
            code: code.to_owned(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let p = self.problem();
        let body = serde_json::to_vec(&p).unwrap_or_default();
        let mut res = (self.status(), body).into_response();
        let h = res.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        match self {
            Self::Unauthorized => {
                h.insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer realm=\"cipherdrop\""),
                );
            }
            Self::InsufficientScope(_) => {
                h.insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static(
                        "Bearer realm=\"cipherdrop\", error=\"insufficient_scope\"",
                    ),
                );
            }
            Self::RateLimited { retry_after_secs } => {
                if let Ok(v) = HeaderValue::from_str(&retry_after_secs.max(1).to_string()) {
                    h.insert(header::RETRY_AFTER, v);
                }
            }
            Self::Overloaded | Self::CapacityExhausted => {
                h.insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
            }
            _ => {}
        }
        res
    }
}

impl From<cipherdrop_storage::StoreError> for ApiError {
    fn from(e: cipherdrop_storage::StoreError) -> Self {
        use cipherdrop_storage::StoreError as S;
        match e {
            S::Unavailable => Self::ShareUnavailable,
            S::Forbidden => Self::Forbidden("Invalid revocation token"),
            S::CapacityExhausted => Self::CapacityExhausted,
            S::TooLarge => Self::PayloadTooLarge,
            S::AccessDenied { destroyed: false } => Self::AccessDenied,
            S::AccessDenied { destroyed: true } => Self::ShareDestroyed,
            S::Duplicate | S::Backend => Self::Internal,
        }
    }
}
