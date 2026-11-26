//! Embedded web interface.
//!
//! The compiled frontend (`frontend/dist`) is embedded into the executable
//! at build time. Lookups are exact-match against the embedded file table,
//! so path traversal is impossible; paths containing `..`, backslashes or
//! empty segments are rejected before lookup anyway.
//!
//! HTML routes **never** touch share storage: opening `/s/{id}` just serves
//! the static application, which consumes only after an explicit click.

use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

use crate::error::ApiError;
use crate::middleware::HTML_CSP;

#[derive(Embed)]
#[folder = "$CIPHERDROP_DIST"]
struct Assets;

fn safe_path(p: &str) -> bool {
    !p.is_empty()
        && !p.contains("..")
        && !p.contains('\\')
        && !p.starts_with('/')
        && !p.contains("//")
        && p.bytes().all(|b| b.is_ascii_graphic())
}

fn html(path: &str) -> Response {
    let Some(file) = Assets::get(path) else {
        return ApiError::NotFound.into_response();
    };
    let mut r = (StatusCode::OK, file.data.into_owned()).into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(HTML_CSP),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// The single-page application shell for `/`, `/s/{id}`, `/revoke/{id}` and `/docs/*`.
pub async fn spa() -> Response {
    html("index.html")
}

/// Swagger UI page generated from `/api/v1/openapi.json`.
pub async fn api_explorer() -> Response {
    html("swagger/index.html")
}

fn serve_file(path: &str, immutable: bool) -> Response {
    if !safe_path(path) {
        return ApiError::NotFound.into_response();
    }
    let Some(file) = Assets::get(path) else {
        return ApiError::NotFound.into_response();
    };
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut r = (StatusCode::OK, file.data.into_owned()).into_response();
    let h = r.headers_mut();
    if let Ok(v) = HeaderValue::from_str(mime.essence_str()) {
        h.insert(header::CONTENT_TYPE, v);
    }
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if immutable {
            "public, max-age=31536000, immutable"
        } else {
            "public, max-age=3600"
        }),
    );
    r
}

/// Content-hashed build assets.
pub async fn asset(Path(path): Path<String>) -> Response {
    serve_file(&format!("assets/{path}"), true)
}

/// Bundled Swagger UI assets.
pub async fn swagger_asset(Path(path): Path<String>) -> Response {
    serve_file(&format!("swagger/{path}"), false)
}

pub async fn favicon() -> Response {
    serve_file("favicon.svg", false)
}

pub async fn robots() -> Response {
    let mut r = "User-agent: *\nDisallow: /\n".into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_rejected() {
        for p in [
            "../Cargo.toml",
            "a/../../b",
            "/etc/passwd",
            "a\\b",
            "a//b",
            "",
            "a b",
        ] {
            assert!(!safe_path(p), "{p}");
        }
        assert!(safe_path("assets/index-abc123.js"));
    }
}
