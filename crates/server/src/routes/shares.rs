//! Share endpoints: create, consume, status, revoke.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use cipherdrop_protocol::api::{
    ConsumeShareRequest, ConsumeShareResponse, CreateShareRequest, CreateShareResponse, Problem,
    Scope, ShareStatusResponse, StorageBackend,
};
use cipherdrop_protocol::encoding::b64_encode;
use cipherdrop_protocol::url::{
    RevocationLink, ShareId, share_url_without_key, validate_revocation_token,
};
use cipherdrop_protocol::{Algorithm, DecodedKdf, PROTOCOL_VERSION, ProtocolError};
use cipherdrop_storage::{
    AccessCheck, Consumed, NewShare, RevokeAuth, ShareMeta, Status, StoreError, StoredEnvelope,
    Verifier,
};

use crate::config::Backend;
use crate::error::ApiError;
use crate::extract::{Principal, StrictJson};
use crate::idempotency::{self, Claim};
use crate::metrics::Metrics;
use crate::net::{ClientInfo, rate_key};
use crate::state::AppState;
use crate::util::{now_unix, random_b64, random_bytes, rfc3339};

/// Header carrying the anonymous revocation capability.
pub const REVOCATION_HEADER: &str = "x-revocation-token";

fn no_store<T: IntoResponse>(r: T) -> Response {
    let mut res = r.into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn parse_id(id: &str) -> Result<ShareId, ApiError> {
    ShareId::parse(id).map_err(|_| ApiError::InvalidRequest("Malformed share id"))
}

fn check_ip_limit(state: &AppState, client: &ClientInfo, create: bool) -> Result<(), ApiError> {
    if !state.config.rate_limit.enabled {
        return Ok(());
    }
    let key = rate_key(client.ip, state.limiters.v6_prefix);
    let lim = if create {
        &state.limiters.create
    } else {
        &state.limiters.read
    };
    lim.check_key(&key).map_err(|_| {
        Metrics::inc(&state.metrics.rate_limited);
        ApiError::RateLimited {
            retry_after_secs: 60,
        }
    })
}

/// Retrieval authorization shared by consume and status.
fn authorize_retrieval(
    state: &AppState,
    principal: &Principal,
    client: &ClientInfo,
) -> Result<(), ApiError> {
    match principal {
        Principal::Token(_) => principal.require(Scope::SharesConsume).map(|_| ()),
        Principal::Anonymous if state.config.auth.anonymous_retrieval => {
            check_ip_limit(state, client, false)
        }
        Principal::Anonymous => Err(ApiError::Unauthorized),
    }
}

/// Create an encrypted share.
///
/// The body contains only the client-side encryption envelope and limits.
/// The server never receives plaintext, keys or passwords, and cannot verify
/// that the payload was actually encrypted.
#[utoipa::path(
    post,
    path = "/api/v1/shares",
    tag = "shares",
    request_body(content = CreateShareRequest, content_type = "application/json"),
    params(
        ("Idempotency-Key" = Option<String>, Header, description = "Optional; 1..=128 visible ASCII characters. Replays the original response for an identical body within the idempotency TTL."),
    ),
    responses(
        (status = 201, description = "Share created", body = CreateShareResponse),
        (status = 400, description = "Invalid envelope or limits", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope or feature disabled", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Payload too large", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Content-Type must be application/json", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Idempotency key reused with a different body", body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited or quota exceeded", body = Problem, content_type = "application/problem+json"),
        (status = 507, description = "Storage capacity exhausted", body = Problem, content_type = "application/problem+json"),
    ),
    security((), ("bearer" = []))
)]
pub async fn create_share(
    State(state): State<AppState>,
    client: ClientInfo,
    principal: Principal,
    headers: HeaderMap,
    body: StrictJson<CreateShareRequest>,
) -> Result<Response, ApiError> {
    let cfg = &state.config;
    let now = now_unix();

    // --- authorization ---
    match &principal {
        Principal::Token(_) => {
            principal.require(Scope::SharesCreate)?;
        }
        Principal::Anonymous if cfg.auth.anonymous_creation => {
            check_ip_limit(&state, &client, true)?
        }
        Principal::Anonymous => return Err(ApiError::Unauthorized),
    }
    let req = &body.value;

    // --- envelope validation (opaque, but strictly shaped) ---
    let max = usize::try_from(cfg.shares.max_size_bytes).unwrap_or(usize::MAX);
    let decoded = req.envelope().decode(max).map_err(|e| match e {
        ProtocolError::TooLarge => ApiError::PayloadTooLarge,
        ProtocolError::UnsupportedVersion => {
            ApiError::InvalidRequest("Unsupported protocol version")
        }
        ProtocolError::KdfBounds(_) => {
            ApiError::InvalidRequest("KDF parameters out of bounds; see GET /api/v1/config")
        }
        _ => ApiError::InvalidRequest("Malformed encryption envelope"),
    })?;

    // --- server-enforced password gate ---
    let access = match &req.access_verifier {
        // Password-protected shares must be gated, so that holding the link
        // without the password is never enough to burn the share.
        None if decoded.kdf.is_some() => {
            return Err(ApiError::InvalidRequest(
                "access_verifier is required for password-protected (kdf) shares",
            ));
        }
        None => None,
        Some(_) if decoded.kdf.is_none() => {
            return Err(ApiError::InvalidRequest(
                "access_verifier is only valid for password-protected (kdf) shares",
            ));
        }
        Some(v) => Some(Verifier(
            cipherdrop_protocol::encoding::b64_decode_array::<32>(v, "access_verifier")
                .map_err(|_| ApiError::InvalidRequest("Malformed access_verifier"))?,
        )),
    };

    // --- storage backend ---
    let backend = match req.storage {
        Some(b) => b,
        None => match cfg.storage.default_backend {
            Backend::Memory => StorageBackend::Memory,
            Backend::Persistent => StorageBackend::Persistent,
        },
    };
    if backend == StorageBackend::Persistent {
        if !cfg.storage.persistent_enabled {
            return Err(ApiError::FeatureDisabled(
                "Persistent storage is disabled on this instance",
            ));
        }
        principal.require(Scope::SharesCreatePersistent)?;
    }

    // --- lifetime ---
    let sh = &cfg.shares;
    let expires_at = match req.ttl_seconds {
        None => Some(now + sh.default_ttl_seconds),
        Some(None) => {
            if !sh.allow_permanent {
                return Err(ApiError::FeatureDisabled(
                    "Shares without expiry are disabled on this instance",
                ));
            }
            principal.require(Scope::SharesCreatePersistent)?;
            None
        }
        Some(Some(t)) if (sh.min_ttl_seconds..=sh.max_ttl_seconds).contains(&t) => Some(now + t),
        Some(Some(_)) => {
            return Err(ApiError::InvalidRequest(
                "ttl_seconds outside the allowed range; see GET /api/v1/config",
            ));
        }
    };
    let max_reads = match req.max_reads {
        None => Some(sh.default_max_reads),
        Some(None) if sh.allow_unlimited_reads => None,
        Some(None) => {
            return Err(ApiError::FeatureDisabled(
                "Unlimited retrievals are disabled on this instance",
            ));
        }
        Some(Some(n)) if (1..=sh.max_reads).contains(&n) => Some(n),
        Some(Some(_)) => {
            return Err(ApiError::InvalidRequest(
                "max_reads outside the allowed range; see GET /api/v1/config",
            ));
        }
    };

    // --- idempotency ---
    let idem_key = match headers.get("idempotency-key") {
        None => None,
        Some(v) => {
            let k = v
                .to_str()
                .ok()
                .filter(|k| idempotency::valid_key(k))
                .ok_or(ApiError::InvalidRequest("Malformed Idempotency-Key header"))?;
            Some(k.to_owned())
        }
    };
    let principal_key = principal.key(&client);
    let mut idem_active = false;
    if let Some(k) = &idem_key {
        match state.idempotency.claim(&principal_key, k, &body.raw, now) {
            Claim::Proceed => idem_active = true,
            Claim::Uncached => {}
            Claim::Replay(r) => return Ok(no_store((StatusCode::CREATED, Json(*r)))),
            Claim::Conflict => return Err(ApiError::IdempotencyConflict),
            Claim::InFlight => {
                return Err(ApiError::RateLimited {
                    retry_after_secs: 1,
                });
            }
        }
    }

    let spec = ShareSpec {
        backend,
        decoded,
        access,
        expires_at,
        max_reads,
    };
    let result = insert_share(&state, &principal, spec, now).await;
    match (&result, &idem_key) {
        (Ok(resp), Some(k)) if idem_active => state.idempotency.complete(&principal_key, k, resp),
        (Err(_), Some(k)) if idem_active => state.idempotency.abandon(&principal_key, k),
        _ => {}
    }
    let resp = result?;
    let mut res = no_store((StatusCode::CREATED, Json(resp)));
    if let Ok(v) = HeaderValue::from_str("/api/v1/shares") {
        res.headers_mut().insert(header::CONTENT_LOCATION, v);
    }
    Ok(res)
}

/// Validated parameters of a share to create.
struct ShareSpec {
    backend: StorageBackend,
    decoded: cipherdrop_protocol::DecodedEnvelope,
    access: Option<Verifier>,
    expires_at: Option<u64>,
    max_reads: Option<u32>,
}

async fn insert_share(
    state: &AppState,
    principal: &Principal,
    spec: ShareSpec,
    now: u64,
) -> Result<CreateShareResponse, ApiError> {
    let ShareSpec {
        backend,
        decoded,
        access,
        expires_at,
        max_reads,
    } = spec;
    if let Principal::Token(t) = principal {
        t.charge_create(now)?;
    }
    let id = ShareId::from_bytes(random_bytes::<16>()?);
    let revocation_token = zeroize::Zeroizing::new(random_b64::<32>()?);
    let share = NewShare {
        envelope: StoredEnvelope {
            nonce: decoded.nonce,
            ciphertext: decoded.ciphertext,
            kdf: decoded.kdf,
        },
        meta: ShareMeta {
            created_at: now,
            expires_at,
            remaining_reads: max_reads,
        },
        revocation: Verifier::from_secret(revocation_token.as_bytes()),
        access,
    };
    let res = match backend {
        StorageBackend::Memory => state.memory.insert(id, share, now),
        StorageBackend::Persistent => {
            #[cfg(feature = "sqlite")]
            {
                let store = state
                    .persistent_shares()
                    .cloned()
                    .ok_or(ApiError::Internal)?;
                tokio::task::spawn_blocking(move || store.insert(&id, &share, now))
                    .await
                    .map_err(|_| ApiError::Internal)?
            }
            #[cfg(not(feature = "sqlite"))]
            {
                drop(share);
                return Err(ApiError::FeatureDisabled(
                    "Persistent storage is not available",
                ));
            }
        }
    };
    if let Err(e) = res {
        if e == StoreError::CapacityExhausted {
            Metrics::inc(&state.metrics.rejected_capacity);
        }
        return Err(e.into());
    }
    Metrics::inc(match backend {
        StorageBackend::Memory => &state.metrics.created_memory,
        StorageBackend::Persistent => &state.metrics.created_persistent,
    });
    let base = state.config.public_base();
    Ok(CreateShareResponse {
        id: id.to_string(),
        url: share_url_without_key(base, &id),
        created_at: rfc3339(now),
        expires_at: expires_at.map(rfc3339),
        max_reads,
        storage: backend,
        revocation_url: RevocationLink::format(base, &id, &revocation_token),
        revocation_token: revocation_token.to_string(),
    })
}

/// Atomically consume one retrieval and return the ciphertext.
///
/// This is the **only** endpoint that returns ciphertext. Validation and
/// decrement happen atomically: for a one-time share, at most one of any
/// number of concurrent requests succeeds. Do **not** retry automatically:
/// a lost response after a successful consume cannot be recovered.
///
/// Requires `Content-Type: application/json` and a JSON body (`{}`, or
/// `{"access_key": "..."}` for password-gated shares); this makes the request
/// non-simple, so browsers cannot send it cross-site without a CORS preflight.
///
/// For shares created with an `access_verifier`, the ciphertext is released
/// only when `access_key` matches; a wrong or missing key returns `403
/// access_denied` and consumes nothing. After `max_access_failures` wrong
/// attempts the share is destroyed (`410 share_destroyed`).
#[utoipa::path(
    post,
    path = "/api/v1/shares/{id}/consume",
    tag = "shares",
    params(("id" = String, Path, description = "Share id (22 characters)")),
    request_body(content = ConsumeShareRequest, content_type = "application/json", example = json!({})),
    responses(
        (status = 200, description = "Ciphertext envelope", body = ConsumeShareResponse),
        (status = 400, description = "Malformed id or body", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Missing or wrong access key (nothing consumed)", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Share unavailable (unknown, expired, consumed or revoked)", body = Problem, content_type = "application/problem+json"),
        (status = 410, description = "Destroyed after too many wrong access keys", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Content-Type must be application/json", body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = Problem, content_type = "application/problem+json"),
    ),
    security((), ("bearer" = []))
)]
pub async fn consume_share(
    State(state): State<AppState>,
    client: ClientInfo,
    principal: Principal,
    Path(id): Path<String>,
    body: StrictJson<ConsumeShareRequest>,
) -> Result<Response, ApiError> {
    authorize_retrieval(&state, &principal, &client)?;
    let id = parse_id(&id)?;
    let access_key = body
        .value
        .access_key
        .as_deref()
        .map(|k| {
            cipherdrop_protocol::encoding::b64_decode_array::<32>(k, "access_key")
                .map(zeroize::Zeroizing::new)
                .map_err(|_| ApiError::InvalidRequest("Malformed access_key"))
        })
        .transpose()?;
    let max_failures = state.config.shares.max_access_failures;
    let now = now_unix();
    let check = AccessCheck {
        key: access_key.as_ref().map(|k| &k[..]),
        max_failures,
    };
    let (consumed, backend) = match state.memory.consume(&id, now, check) {
        Ok(c) => (c, StorageBackend::Memory),
        Err(StoreError::Unavailable) => (
            consume_persistent(
                &state,
                id,
                now,
                access_key.as_ref().map(|k| **k),
                max_failures,
            )
            .await?,
            StorageBackend::Persistent,
        ),
        Err(e) => return Err(e.into()),
    };
    Metrics::inc(match backend {
        StorageBackend::Memory => &state.metrics.consumed_memory,
        StorageBackend::Persistent => &state.metrics.consumed_persistent,
    });
    let env = consumed.envelope.as_ref();
    let body = ConsumeShareResponse {
        version: PROTOCOL_VERSION,
        algorithm: Algorithm::Aes256Gcm,
        nonce: b64_encode(&env.nonce),
        ciphertext: b64_encode(&env.ciphertext),
        kdf: env.kdf.as_ref().map(DecodedKdf::to_wire),
        remaining_reads: consumed.remaining_reads,
        expires_at: consumed.expires_at.map(rfc3339),
    };
    Ok(no_store(Json(body)))
}

async fn consume_persistent(
    state: &AppState,
    id: ShareId,
    now: u64,
    access_key: Option<[u8; 32]>,
    max_failures: u32,
) -> Result<Consumed, ApiError> {
    #[cfg(feature = "sqlite")]
    if let Some(store) = state.persistent_shares().cloned() {
        return match tokio::task::spawn_blocking(move || {
            let k = zeroize::Zeroizing::new(access_key);
            store.consume(
                &id,
                now,
                AccessCheck {
                    key: k.as_ref().map(|k| &k[..]),
                    max_failures,
                },
            )
        })
        .await
        {
            Ok(Ok(c)) => Ok(c),
            Ok(Err(e)) => {
                if e == StoreError::Unavailable {
                    Metrics::inc(&state.metrics.consume_unavailable);
                }
                Err(e.into())
            }
            Err(_) => Err(ApiError::Internal),
        };
    }
    let _ = (id, now, access_key, max_failures);
    Metrics::inc(&state.metrics.consume_unavailable);
    Err(ApiError::ShareUnavailable)
}

/// Non-consuming status check.
///
/// Safe for link checkers and monitoring: never decrements the read counter.
#[utoipa::path(
    get,
    path = "/api/v1/shares/{id}/status",
    tag = "shares",
    params(("id" = String, Path, description = "Share id (22 characters)")),
    responses(
        (status = 200, description = "Share is available", body = ShareStatusResponse),
        (status = 400, description = "Malformed id", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Share unavailable", body = Problem, content_type = "application/problem+json"),
    ),
    security((), ("bearer" = []))
)]
pub async fn share_status(
    State(state): State<AppState>,
    client: ClientInfo,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    authorize_retrieval(&state, &principal, &client)?;
    let id = parse_id(&id)?;
    let now = now_unix();
    let (st, backend): (Status, StorageBackend) = if let Some(s) = state.memory.status(&id, now) {
        (s, StorageBackend::Memory)
    } else {
        (
            status_persistent(&state, id, now).await?,
            StorageBackend::Persistent,
        )
    };
    Ok(no_store(Json(ShareStatusResponse {
        available: true,
        expires_at: st.expires_at.map(rfc3339),
        remaining_reads: st.remaining_reads,
        password_protected: st.password_protected,
        access_protected: st.access_protected,
        kdf: st.kdf.as_ref().map(DecodedKdf::to_wire),
        storage: backend,
    })))
}

async fn status_persistent(state: &AppState, id: ShareId, now: u64) -> Result<Status, ApiError> {
    #[cfg(feature = "sqlite")]
    if let Some(store) = state.persistent_shares().cloned() {
        return tokio::task::spawn_blocking(move || store.status(&id, now))
            .await
            .map_err(|_| ApiError::Internal)?
            .map_err(ApiError::from)?
            .ok_or(ApiError::ShareUnavailable);
    }
    let _ = (state, id, now);
    Err(ApiError::ShareUnavailable)
}

/// Revoke (delete) a share.
///
/// Authorize with the share's revocation token in `X-Revocation-Token`, or
/// with an API token holding `shares:revoke`. Administrators can revoke but
/// can never decrypt.
#[utoipa::path(
    delete,
    path = "/api/v1/shares/{id}",
    tag = "shares",
    params(
        ("id" = String, Path, description = "Share id (22 characters)"),
        ("X-Revocation-Token" = Option<String>, Header, description = "Revocation token returned at creation"),
    ),
    responses(
        (status = 204, description = "Share revoked"),
        (status = 400, description = "Malformed id or token", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "No revocation credential", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Invalid revocation token", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Share unavailable", body = Problem, content_type = "application/problem+json"),
    ),
    security((), ("bearer" = []))
)]
pub async fn revoke_share(
    State(state): State<AppState>,
    client: ClientInfo,
    principal: Principal,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let id = parse_id(&id)?;
    let token = headers
        .get(REVOCATION_HEADER)
        .map(|v| {
            v.to_str()
                .map(str::to_owned)
                .map_err(|_| ApiError::InvalidRequest("Malformed revocation token"))
        })
        .transpose()?;
    let token = zeroize::Zeroizing::new(token);
    let admin = principal.has(Scope::SharesRevoke);
    if !admin {
        if matches!(principal, Principal::Token(_)) && token.is_none() {
            return Err(ApiError::InsufficientScope(
                "Requires scope shares:revoke or a revocation token",
            ));
        }
        let Some(t) = token.as_deref() else {
            return Err(ApiError::Unauthorized);
        };
        validate_revocation_token(t)
            .map_err(|_| ApiError::InvalidRequest("Malformed revocation token"))?;
        check_ip_limit(&state, &client, false)?;
    }
    let now = now_unix();
    let auth_bytes: Option<Vec<u8>> = if admin {
        None
    } else {
        token.as_deref().map(|t| t.as_bytes().to_vec())
    };
    let mem = {
        let auth = auth_bytes
            .as_deref()
            .map_or(RevokeAuth::Admin, RevokeAuth::Token);
        state.memory.revoke(&id, auth, now)
    };
    let res = match mem {
        Err(StoreError::Unavailable) => revoke_persistent(&state, id, auth_bytes, now).await,
        other => other.map_err(ApiError::from),
    };
    res?;
    Metrics::inc(&state.metrics.revoked);
    Ok(no_store(StatusCode::NO_CONTENT))
}

async fn revoke_persistent(
    state: &AppState,
    id: ShareId,
    auth: Option<Vec<u8>>,
    now: u64,
) -> Result<(), ApiError> {
    #[cfg(feature = "sqlite")]
    if let Some(store) = state.persistent_shares().cloned() {
        return tokio::task::spawn_blocking(move || {
            let a = auth.as_deref().map_or(RevokeAuth::Admin, RevokeAuth::Token);
            store.revoke(&id, a, now)
        })
        .await
        .map_err(|_| ApiError::Internal)?
        .map_err(ApiError::from);
    }
    let _ = (state, id, auth, now);
    Err(ApiError::ShareUnavailable)
}
