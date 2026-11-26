//! OpenAPI document generated from the actual handler annotations and the
//! protocol crate's schema types.

use utoipa::OpenApi;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::server::Server;

use crate::routes::{admin, meta, shares};

#[derive(OpenApi, Debug)]
#[openapi(
    info(
        title = "CipherDrop API",
        description = "Zero-knowledge secret sharing. Clients encrypt locally (AES-256-GCM, protocol v1) and upload only ciphertext. The decryption key travels exclusively in the URL fragment (`#v1.<key>`), which is never sent to the server.\n\nThe server cannot verify that uploaded payloads are actually encrypted; it treats them as opaque, untrusted bytes.\n\nAll errors use RFC 9457 Problem Details (`application/problem+json`).",
        license(name = "MIT"),
    ),
    paths(
        shares::create_share,
        shares::consume_share,
        shares::share_status,
        shares::revoke_share,
        meta::get_config,
        meta::get_version,
        meta::get_openapi,
        admin::create_token,
        admin::list_tokens,
        admin::revoke_token,
        meta::healthz,
        meta::readyz,
        meta::metrics,
    ),
    components(schemas(
        cipherdrop_protocol::api::CreateShareRequest,
        cipherdrop_protocol::api::CreateShareResponse,
        cipherdrop_protocol::api::ConsumeShareResponse,
        cipherdrop_protocol::api::ShareStatusResponse,
        cipherdrop_protocol::api::ConfigResponse,
        cipherdrop_protocol::api::VersionResponse,
        cipherdrop_protocol::api::KdfLimits,
        cipherdrop_protocol::api::Problem,
        cipherdrop_protocol::api::StorageBackend,
        cipherdrop_protocol::api::Scope,
        cipherdrop_protocol::api::CreateTokenRequest,
        cipherdrop_protocol::api::CreateTokenResponse,
        cipherdrop_protocol::api::TokenInfo,
        cipherdrop_protocol::KdfParams,
        cipherdrop_protocol::Algorithm,
        cipherdrop_protocol::KdfAlgorithm,
        shares::ConsumeRequest,
    )),
    tags(
        (name = "shares", description = "Create, retrieve, inspect and revoke encrypted shares"),
        (name = "instance", description = "Public instance information"),
        (name = "admin", description = "API token administration (admin:manage)"),
        (name = "operations", description = "Health, readiness and metrics"),
    )
)]
pub struct ApiDoc;

/// Render the OpenAPI JSON for a given public base URL.
#[must_use]
pub fn render(public_base: &str) -> String {
    let mut doc = ApiDoc::openapi();
    doc.info.version = env!("CARGO_PKG_VERSION").to_owned();
    doc.servers = Some(vec![Server::new(public_base)]);
    let components = doc.components.get_or_insert_with(Default::default);
    components.add_security_scheme(
        "bearer",
        SecurityScheme::Http(
            HttpBuilder::new()
                .scheme(HttpAuthScheme::Bearer)
                .bearer_format("cdt_{id}_{secret}")
                .description(Some("Scoped API token"))
                .build(),
        ),
    );
    doc.to_pretty_json().unwrap_or_else(|_| "{}".into())
}
