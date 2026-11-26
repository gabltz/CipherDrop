//! End-to-end API behaviour against the real router (no network).

mod common;

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use cipherdrop_protocol::api::{
    ConsumeShareResponse, CreateShareRequest, CreateShareResponse, StorageBackend,
};
use cipherdrop_protocol::crypto::{KdfCost, ShareKey, decrypt_payload, encrypt_payload};
use cipherdrop_protocol::envelope::kdf_bounds;
use cipherdrop_protocol::payload::SecretPayload;
use common::*;

#[tokio::test]
async fn full_lifecycle_roundtrip_one_time() {
    let (app, _) = app("");
    let (req, key) = encrypted_request("synthetic secret: hunter2-not-real");
    let created = create(&app, &req).await;

    // Server-produced URL has no fragment and no key material.
    assert_eq!(
        created.url,
        format!("https://paste.example.test/s/{}", created.id)
    );
    assert!(!created.url.contains('#'));
    assert_eq!(created.id.len(), 22);
    assert_eq!(created.max_reads, Some(1));
    assert_eq!(created.storage, StorageBackend::Memory);
    assert!(created.expires_at.is_some());
    assert_eq!(created.revocation_token.len(), 43);
    assert!(created.revocation_url.ends_with(&format!(
        "/revoke/{}#v1.{}",
        created.id, created.revocation_token
    )));

    let r = consume(&app, &created.id).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers["cache-control"], "no-store");
    let c: ConsumeShareResponse = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(c.remaining_reads, Some(0));
    let env = c.envelope().decode(usize::MAX).unwrap();
    let pt = decrypt_payload(&key, &env, None).unwrap();
    assert_eq!(pt.content, "synthetic secret: hunter2-not-real");

    // Burned.
    let r = consume(&app, &created.id).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.code(), "share_unavailable");
    assert_eq!(r.headers["content-type"], "application/problem+json");
}

#[tokio::test]
async fn password_share_without_access_verifier_is_rejected() {
    let (app, _) = app("");
    let key = ShareKey::generate().unwrap();
    let cost = KdfCost {
        memory_kib: kdf_bounds::MIN_MEMORY_KIB,
        iterations: kdf_bounds::MIN_ITERATIONS,
        parallelism: 1,
    };
    let env = encrypt_payload(
        &key,
        &SecretPayload::text("ungated"),
        Some(("pw", cost)),
        256,
    )
    .unwrap();
    let r = send(
        &app,
        Req::post("/api/v1/shares").json(&CreateShareRequest::from_envelope(env.to_wire())),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn hundred_concurrent_consumes_yield_one_ciphertext() {
    for _ in 0..5 {
        let (app, _) = app("");
        let (req, _) = encrypted_request("race");
        let created = create(&app, &req).await;
        let id = Arc::new(created.id);
        let barrier = Arc::new(tokio::sync::Barrier::new(100));
        let mut tasks = Vec::new();
        for _ in 0..100 {
            let (app, id, b) = (app.clone(), Arc::clone(&id), Arc::clone(&barrier));
            tasks.push(tokio::spawn(async move {
                b.wait().await;
                consume(&app, &id).await.status
            }));
        }
        let mut ok = 0;
        for t in tasks {
            match t.await.unwrap() {
                StatusCode::OK => ok += 1,
                StatusCode::NOT_FOUND => {}
                s => panic!("unexpected status {s}"),
            }
        }
        assert_eq!(ok, 1);
    }
}

#[tokio::test]
async fn page_loads_status_and_head_never_consume() {
    let (app, _) = app("");
    let (req, _) = encrypted_request("scanner-proof");
    let created = create(&app, &req).await;
    for _ in 0..3 {
        let r = send(&app, Req::get(format!("/s/{}", created.id))).await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(
            r.headers["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("script-src 'self'")
        );
        let r = send(&app, Req::new(Method::HEAD, format!("/s/{}", created.id))).await;
        assert_eq!(r.status, StatusCode::OK);
        let r = send(
            &app,
            Req::get(format!("/api/v1/shares/{}/status", created.id)),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.json()["remaining_reads"], 1);
        let r = send(
            &app,
            Req::new(
                Method::HEAD,
                format!("/api/v1/shares/{}/status", created.id),
            ),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        // GET on the consume endpoint is not allowed.
        let r = send(
            &app,
            Req::get(format!("/api/v1/shares/{}/consume", created.id)),
        )
        .await;
        assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    }
    assert_eq!(consume(&app, &created.id).await.status, StatusCode::OK);
}

#[tokio::test]
async fn consume_requires_json_and_same_origin() {
    let (app, _) = app("");
    let (req, _) = encrypted_request("csrf");
    let created = create(&app, &req).await;
    let uri = format!("/api/v1/shares/{}/consume", created.id);
    // Simple (form-like) request without JSON content type.
    let r = send(&app, Req::post(&uri)).await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let r = send(
        &app,
        Req::post(&uri)
            .header("content-type", "text/plain")
            .header("origin", "https://paste.example.test"),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // Foreign origin.
    let r = send(
        &app,
        Req::post(&uri)
            .raw_json("{}")
            .header("origin", "https://evil.example"),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.code(), "cross_origin_rejected");
    let r = send(
        &app,
        Req::post(&uri)
            .raw_json("{}")
            .header("sec-fetch-site", "cross-site"),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Unknown body fields rejected.
    let r = send(&app, Req::post(&uri).raw_json("{\"x\":1}")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // None of the above consumed the share; same-origin succeeds.
    let r = send(
        &app,
        Req::post(&uri)
            .raw_json("{}")
            .header("origin", "https://paste.example.test"),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn cors_allowlist() {
    let (app, _) = app("[cors]\nallowed_origins = [\"https://app.example.org\"]\n");
    let r = send(
        &app,
        Req::new(Method::OPTIONS, "/api/v1/shares")
            .header("origin", "https://app.example.org")
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type"),
    )
    .await;
    assert_eq!(
        r.headers["access-control-allow-origin"],
        "https://app.example.org"
    );
    let (req, _) = encrypted_request("cors");
    let r = send(
        &app,
        Req::post("/api/v1/shares")
            .json(&req)
            .header("origin", "https://app.example.org"),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = send(
        &app,
        Req::post("/api/v1/shares")
            .json(&req)
            .header("origin", "https://other.example.org"),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Default: no CORS headers at all.
    let (app, _) = common::app("");
    let r = send(
        &app,
        Req::get("/api/v1/config").header("origin", "https://app.example.org"),
    )
    .await;
    assert!(!r.headers.contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn limited_reads_and_status() {
    let (app, _) = app("");
    let (mut req, _) = encrypted_request("three reads");
    req.max_reads = Some(Some(3));
    let created = create(&app, &req).await;
    for expected in [2, 1, 0] {
        let r = consume(&app, &created.id).await;
        assert_eq!(r.json()["remaining_reads"], expected);
    }
    assert_eq!(
        consume(&app, &created.id).await.status,
        StatusCode::NOT_FOUND
    );
    let r = send(
        &app,
        Req::get(format!("/api/v1/shares/{}/status", created.id)),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn expiry_is_enforced_on_read() {
    let (app, _) = app("[shares]\nmin_ttl_seconds = 1\n");
    let (mut req, _) = encrypted_request("short-lived");
    req.ttl_seconds = Some(Some(1));
    req.max_reads = Some(Some(5));
    let created = create(&app, &req).await;
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert_eq!(
        consume(&app, &created.id).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn input_validation() {
    let (app, _) = app("[shares]\nmax_size_bytes = 2048\n");
    let (good, _) = encrypted_request("x");
    let post = |body: String| Req::post("/api/v1/shares").raw_json(&body);

    let mut v = serde_json::to_value(&good).unwrap();
    v["nonce"] = "not base64!".into();
    assert_eq!(
        send(&app, post(v.to_string())).await.status,
        StatusCode::BAD_REQUEST
    );

    let mut v = serde_json::to_value(&good).unwrap();
    v["plaintext"] = "should never be accepted".into();
    let r = send(&app, post(v.to_string())).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(
        !r.text().contains("should never be accepted"),
        "errors never echo input"
    );

    let mut v = serde_json::to_value(&good).unwrap();
    v["version"] = 2.into();
    assert_eq!(
        send(&app, post(v.to_string())).await.status,
        StatusCode::BAD_REQUEST
    );

    let mut v = serde_json::to_value(&good).unwrap();
    v["algorithm"] = "AES-128-CBC".into();
    assert_eq!(
        send(&app, post(v.to_string())).await.status,
        StatusCode::BAD_REQUEST
    );

    for (ttl, status) in [(0u64, 400), (59, 400), (604_801, 400), (60, 201)] {
        let mut v = serde_json::to_value(&good).unwrap();
        v["ttl_seconds"] = ttl.into();
        assert_eq!(
            send(&app, post(v.to_string())).await.status.as_u16(),
            status,
            "ttl {ttl}"
        );
    }
    for (reads, status) in [(0u32, 400), (101, 400), (100, 201)] {
        let mut v = serde_json::to_value(&good).unwrap();
        v["max_reads"] = reads.into();
        assert_eq!(
            send(&app, post(v.to_string())).await.status.as_u16(),
            status,
            "reads {reads}"
        );
    }
    // Permanent and unlimited are disabled by default.
    let mut v = serde_json::to_value(&good).unwrap();
    v["ttl_seconds"] = serde_json::Value::Null;
    assert_eq!(
        send(&app, post(v.to_string())).await.status,
        StatusCode::FORBIDDEN
    );
    let mut v = serde_json::to_value(&good).unwrap();
    v["max_reads"] = serde_json::Value::Null;
    assert_eq!(
        send(&app, post(v.to_string())).await.status,
        StatusCode::FORBIDDEN
    );

    // Oversized ciphertext.
    let key = ShareKey::generate().unwrap();
    let big = encrypt_payload(&key, &SecretPayload::text("A".repeat(4096)), None, 0).unwrap();
    let r = send(
        &app,
        Req::post("/api/v1/shares").json(&CreateShareRequest::from_envelope(big.to_wire())),
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    // Body far beyond the transport limit.
    let r = send(
        &app,
        post(format!("{{\"pad\":\"{}\"}}", "A".repeat(64 * 1024))),
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    // Malformed JSON and wrong content type.
    assert_eq!(
        send(&app, post("{".into())).await.status,
        StatusCode::BAD_REQUEST
    );
    let r = send(
        &app,
        Req::post("/api/v1/shares").header("content-type", "text/plain"),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // Malformed share ids.
    let r = send(
        &app,
        Req::post("/api/v1/shares/..%2F..%2Fetc/consume").raw_json("{}"),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = send(&app, Req::get("/api/v1/shares/short/status")).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn revocation() {
    let (app, _) = app("");
    let (mut req, _) = encrypted_request("revoke me");
    req.max_reads = Some(Some(5));
    let created = create(&app, &req).await;
    let uri = format!("/api/v1/shares/{}", created.id);
    assert_eq!(
        send(&app, Req::delete(&uri)).await.status,
        StatusCode::UNAUTHORIZED
    );
    let wrong = "A".repeat(43);
    let r = send(&app, Req::delete(&uri).header("x-revocation-token", wrong)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = send(
        &app,
        Req::delete(&uri).header("x-revocation-token", "malformed"),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = send(
        &app,
        Req::delete(&uri).header("x-revocation-token", &created.revocation_token),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(
        consume(&app, &created.id).await.status,
        StatusCode::NOT_FOUND
    );
    let r = send(
        &app,
        Req::delete(&uri).header("x-revocation-token", &created.revocation_token),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn authentication_modes_and_scopes() {
    let (creator, c_snip) = token(&["shares:create"]);
    let (reader, r_snip) = token(&["shares:consume"]);
    let (admin, a_snip) = token(&["shares:revoke", "admin:manage"]);
    let cfg = format!(
        "[auth]\nanonymous_creation = false\nanonymous_retrieval = false\n{c_snip}{r_snip}{a_snip}"
    );
    let (app, _) = app(&cfg);
    let (req, _) = encrypted_request("authn");

    // Anonymous creation disabled.
    let r = send(&app, Req::post("/api/v1/shares").json(&req)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.headers.contains_key("www-authenticate"));
    // Invalid token is an error, not anonymous.
    let r = send(
        &app,
        Req::post("/api/v1/shares")
            .json(&req)
            .bearer("cdt_000000000000_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Wrong scope.
    let r = send(&app, Req::post("/api/v1/shares").json(&req).bearer(&reader)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.code(), "insufficient_scope");
    // Correct scope.
    let r = send(
        &app,
        Req::post("/api/v1/shares").json(&req).bearer(&creator),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let created: CreateShareResponse = serde_json::from_slice(&r.body).unwrap();
    // Anonymous retrieval disabled.
    assert_eq!(
        consume(&app, &created.id).await.status,
        StatusCode::UNAUTHORIZED
    );
    let r = send(
        &app,
        Req::get(format!("/api/v1/shares/{}/status", created.id)),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = send(
        &app,
        Req::post(format!("/api/v1/shares/{}/consume", created.id))
            .raw_json("{}")
            .bearer(&creator),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Admin revoke (no revocation token needed).
    let r = send(
        &app,
        Req::delete(format!("/api/v1/shares/{}", created.id)).bearer(&admin),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = send(
        &app,
        Req::post(format!("/api/v1/shares/{}/consume", created.id))
            .raw_json("{}")
            .bearer(&reader),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // Persistent storage disabled on this instance.
    let mut p = req.clone();
    p.storage = Some(StorageBackend::Persistent);
    let r = send(&app, Req::post("/api/v1/shares").json(&p).bearer(&creator)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.code(), "feature_disabled");
}

#[tokio::test]
async fn admin_token_api() {
    let (admin, a_snip) = token(&["admin:manage"]);
    let (app, _) = app(&format!("[auth]\nanonymous_creation = false\n{a_snip}"));
    let body =
        serde_json::json!({"name": "ci", "scopes": ["shares:create"], "daily_create_quota": 1});
    let r = send(&app, Req::post("/api/v1/admin/tokens").json(&body)).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = send(
        &app,
        Req::post("/api/v1/admin/tokens").json(&body).bearer(&admin),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let new_token = r.json()["token"].as_str().unwrap().to_owned();
    let new_id = r.json()["info"]["id"].as_str().unwrap().to_owned();
    // Listing never returns secrets.
    let r = send(&app, Req::get("/api/v1/admin/tokens").bearer(&admin)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(!r.text().contains(&new_token[17..]));
    assert_eq!(r.json().as_array().unwrap().len(), 2);
    // New token works and its daily quota is enforced.
    let (req, _) = encrypted_request("quota");
    let r = send(
        &app,
        Req::post("/api/v1/shares").json(&req).bearer(&new_token),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = send(
        &app,
        Req::post("/api/v1/shares").json(&req).bearer(&new_token),
    )
    .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.code(), "quota_exceeded");
    // The new token cannot administer.
    let r = send(&app, Req::get("/api/v1/admin/tokens").bearer(&new_token)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Revoke it.
    let r = send(
        &app,
        Req::delete(format!("/api/v1/admin/tokens/{new_id}")).bearer(&admin),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = send(
        &app,
        Req::post("/api/v1/shares").json(&req).bearer(&new_token),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Config tokens are immutable through the API.
    let admin_id = &admin[4..16];
    let r = send(
        &app,
        Req::delete(format!("/api/v1/admin/tokens/{admin_id}")).bearer(&admin),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn per_ip_rate_limits() {
    let (app, state) = app("[rate_limit]\ncreate_per_minute = 2\nread_per_minute = 3\n");
    let (req, _) = encrypted_request("rl");
    let mut statuses = Vec::new();
    for _ in 0..3 {
        statuses.push(
            send(&app, Req::post("/api/v1/shares").json(&req))
                .await
                .status
                .as_u16(),
        );
    }
    assert_eq!(statuses, [201, 201, 429]);
    let r = send(&app, Req::post("/api/v1/shares").json(&req)).await;
    assert!(r.headers.contains_key("retry-after"));
    // Different client IP has its own bucket.
    let r = send(
        &app,
        Req::post("/api/v1/shares")
            .json(&req)
            .peer("198.51.100.20:1"),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let id = "AAAAAAAAAAAAAAAAAAAAAA";
    let mut s = Vec::new();
    for _ in 0..4 {
        s.push(
            send(&app, Req::get(format!("/api/v1/shares/{id}/status")))
                .await
                .status
                .as_u16(),
        );
    }
    assert_eq!(s, [404, 404, 404, 429]);
    assert!(
        state
            .metrics
            .rate_limited
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 2
    );
}

#[tokio::test]
async fn forged_forwarded_for_cannot_evade_rate_limit() {
    let (app, _) = app(
        "[rate_limit]\ncreate_per_minute = 1\n[security]\ntrust_forwarded_headers = true\ntrusted_proxies = [\"10.0.0.0/8\"]\n",
    );
    let (req, _) = encrypted_request("xff");
    // Direct client (not a trusted proxy) forging XFF: still keyed by peer IP.
    let r1 = send(
        &app,
        Req::post("/api/v1/shares")
            .json(&req)
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "1.1.1.1"),
    )
    .await;
    let r2 = send(
        &app,
        Req::post("/api/v1/shares")
            .json(&req)
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "2.2.2.2"),
    )
    .await;
    // Untrusted peer cannot claim https either.
    assert_eq!(r1.status, StatusCode::FORBIDDEN);
    assert_eq!(r1.code(), "https_required");
    assert_eq!(r2.status, StatusCode::FORBIDDEN);
    // Via the trusted proxy, forged left-most entries are ignored.
    let via = |xff: &str| {
        Req::post("/api/v1/shares")
            .json(&req)
            .peer("10.0.0.5:1000")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", xff.to_owned())
    };
    assert_eq!(
        send(&app, via("6.6.6.6, 203.0.113.50")).await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        send(&app, via("7.7.7.7, 203.0.113.50")).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Proxy reporting plain http is refused when HTTPS is required.
    let r = send(
        &app,
        Req::get("/api/v1/config")
            .peer("10.0.0.5:1000")
            .header("x-forwarded-proto", "http"),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Probes stay reachable over plain HTTP for orchestrators.
    let r = send(&app, Req::get("/healthz").peer("10.0.0.5:1000")).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn idempotent_creation() {
    let (app, state) = app("");
    let (req, _) = encrypted_request("idem");
    let mk = |key: &str| {
        Req::post("/api/v1/shares")
            .json(&req)
            .header("idempotency-key", key.to_owned())
    };
    let a = send(&app, mk("key-1")).await;
    let b = send(&app, mk("key-1")).await;
    assert_eq!(a.status, StatusCode::CREATED);
    assert_eq!(a.json(), b.json());
    assert_eq!(state.memory.usage().shares, 1);
    let (other, _) = encrypted_request("different");
    let r = send(
        &app,
        Req::post("/api/v1/shares")
            .json(&other)
            .header("idempotency-key", "key-1"),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = send(
        &app,
        Req::post("/api/v1/shares")
            .json(&req)
            .header("idempotency-key", "bad key"),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn capacity_rejects_without_evicting() {
    let (app, state) = app("[storage]\nmax_shares = 3\n");
    let mut ids = Vec::new();
    for _ in 0..3 {
        let (req, _) = encrypted_request("cap");
        ids.push(create(&app, &req).await.id);
    }
    let (req, _) = encrypted_request("cap");
    let r = send(&app, Req::post("/api/v1/shares").json(&req)).await;
    assert_eq!(r.status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(r.code(), "capacity_exhausted");
    for id in &ids {
        assert_eq!(
            send(&app, Req::get(format!("/api/v1/shares/{id}/status")))
                .await
                .status,
            StatusCode::OK
        );
    }
    assert_eq!(state.memory.usage().shares, 3);
}

#[tokio::test]
async fn security_headers_everywhere() {
    let (app, _) = app("");
    for uri in [
        "/",
        "/api/v1/config",
        "/api/v1/nope",
        "/docs/security",
        "/healthz",
    ] {
        let r = send(&app, Req::get(uri)).await;
        let h = &r.headers;
        assert_eq!(h["x-content-type-options"], "nosniff", "{uri}");
        assert_eq!(h["referrer-policy"], "no-referrer", "{uri}");
        assert_eq!(h["x-frame-options"], "DENY", "{uri}");
        assert!(
            h["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'"),
            "{uri}"
        );
        assert!(h.contains_key("permissions-policy"), "{uri}");
        assert!(
            h["x-robots-tag"].to_str().unwrap().contains("noindex"),
            "{uri}"
        );
        assert!(h.contains_key("strict-transport-security"), "{uri}");
        assert!(h.contains_key("cache-control"), "{uri}");
    }
    let r = send(&app, Req::get("/robots.txt")).await;
    assert!(r.text().contains("Disallow: /"));
    let r = send(&app, Req::get("/assets/../../Cargo.toml")).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn instance_endpoints() {
    let (app, _) = app("");
    let r = send(&app, Req::get("/api/v1/config")).await;
    assert_eq!(r.status, StatusCode::OK);
    let j = r.json();
    assert_eq!(j["public_url"], "https://paste.example.test");
    assert_eq!(j["max_ciphertext_bytes"], 1_048_576);
    assert_eq!(j["kdf"]["min_memory_kib"], 19_456);
    let r = send(&app, Req::get("/api/v1/version")).await;
    assert_eq!(r.json()["protocol_versions"][0], 1);
    let r = send(&app, Req::get("/api/v1/openapi.json")).await;
    let doc = r.json();
    for p in [
        "/api/v1/shares",
        "/api/v1/shares/{id}/consume",
        "/api/v1/shares/{id}/status",
        "/api/v1/shares/{id}",
        "/api/v1/config",
        "/api/v1/version",
    ] {
        assert!(doc["paths"][p].is_object(), "missing {p}");
    }
    assert!(doc["components"]["schemas"]["CreateShareRequest"].is_object());
    assert_eq!(doc["servers"][0]["url"], "https://paste.example.test");
    assert_eq!(
        send(&app, Req::get("/healthz")).await.status,
        StatusCode::OK
    );
    assert_eq!(send(&app, Req::get("/readyz")).await.status, StatusCode::OK);
}

#[tokio::test]
async fn metrics_protection_and_bounded_labels() {
    let (app, _) = app("");
    assert_eq!(
        send(&app, Req::get("/metrics")).await.status,
        StatusCode::NOT_FOUND
    );
    let (m, snip) = token(&["admin:metrics"]);
    let (app, _) = common::app(&format!("[metrics]\nenabled = true\n{snip}"));
    let (req, _) = encrypted_request("metrics");
    let created = create(&app, &req).await;
    consume(&app, &created.id).await;
    assert_eq!(
        send(&app, Req::get("/metrics")).await.status,
        StatusCode::UNAUTHORIZED
    );
    let r = send(&app, Req::get("/metrics").bearer(&m)).await;
    assert_eq!(r.status, StatusCode::OK);
    let t = r.text();
    assert!(t.contains("cipherdrop_shares_created_total{storage=\"memory\"} 1"));
    assert!(t.contains("cipherdrop_shares_consumed_total{storage=\"memory\"} 1"));
    assert!(!t.contains(&created.id));
}

fn gated_request(content: &str, password: &str) -> (CreateShareRequest, ShareKey) {
    use cipherdrop_protocol::crypto::encrypt_payload_with_access;
    let key = ShareKey::generate().unwrap();
    let cost = KdfCost {
        memory_kib: kdf_bounds::MIN_MEMORY_KIB,
        iterations: kdf_bounds::MIN_ITERATIONS,
        parallelism: 1,
    };
    let s = encrypt_payload_with_access(
        &key,
        &SecretPayload::text(content),
        Some((password, cost)),
        256,
    )
    .unwrap();
    let mut req = CreateShareRequest::from_envelope(s.envelope.to_wire());
    req.access_verifier = Some(cipherdrop_protocol::encoding::b64_encode(
        &s.access_verifier.unwrap(),
    ));
    (req, key)
}

fn access_key_for(key: &ShareKey, status: &serde_json::Value, password: &str) -> String {
    let kdf: cipherdrop_protocol::KdfParams =
        serde_json::from_value(status["kdf"].clone()).unwrap();
    let keys =
        cipherdrop_protocol::crypto::derive_password_keys(key, &kdf.decode().unwrap(), password)
            .unwrap();
    cipherdrop_protocol::encoding::b64_encode(keys.access_key.as_ref())
}

#[tokio::test]
async fn access_password_is_enforced_by_the_server() {
    let (app, _) = app("[shares]\nmax_access_failures = 3\n");
    let (mut req, key) = gated_request("gated synthetic", "open sesame");
    req.max_reads = Some(Some(2));
    let created = create(&app, &req).await;
    let status = send(
        &app,
        Req::get(format!("/api/v1/shares/{}/status", created.id)),
    )
    .await
    .json();
    assert_eq!(status["password_protected"], true);
    assert_eq!(status["access_protected"], true);
    assert_eq!(status["kdf"]["algorithm"], "argon2id");
    let uri = format!("/api/v1/shares/{}/consume", created.id);

    // Without access key, and with a wrong one: denied, nothing consumed.
    let r = send(&app, Req::post(&uri).raw_json("{}")).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.code(), "access_denied");
    assert!(!r.text().contains("ciphertext"));
    let wrong = access_key_for(&key, &status, "wrong");
    let r = send(
        &app,
        Req::post(&uri).json(&serde_json::json!({ "access_key": wrong })),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let s = send(
        &app,
        Req::get(format!("/api/v1/shares/{}/status", created.id)),
    )
    .await
    .json();
    assert_eq!(s["remaining_reads"], 2, "denied attempts must not consume");
    let r = send(
        &app,
        Req::post(&uri).json(&serde_json::json!({ "access_key": "short" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Correct password: released and decryptable.
    let good = access_key_for(&key, &status, "open sesame");
    let r = send(
        &app,
        Req::post(&uri).json(&serde_json::json!({ "access_key": good })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let c: ConsumeShareResponse = serde_json::from_slice(&r.body).unwrap();
    let env = c.envelope().decode(usize::MAX).unwrap();
    assert_eq!(
        decrypt_payload(&key, &env, Some("open sesame"))
            .unwrap()
            .content,
        "gated synthetic"
    );

    // Third failure (failure budget = 3) destroys the share.
    let r = send(
        &app,
        Req::post(&uri).json(&serde_json::json!({ "access_key": wrong })),
    )
    .await;
    assert_eq!(r.status, StatusCode::GONE);
    assert_eq!(r.code(), "share_destroyed");
    assert_eq!(
        send(
            &app,
            Req::post(&uri).json(&serde_json::json!({ "access_key": good }))
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn access_verifier_requires_kdf() {
    let (app, _) = app("");
    let (mut req, _) = encrypted_request("no kdf");
    req.access_verifier = Some("A".repeat(43));
    let r = send(&app, Req::post("/api/v1/shares").json(&req)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let (mut req, _) = gated_request("x", "pw");
    req.access_verifier = Some("bad".into());
    assert_eq!(
        send(&app, Req::post("/api/v1/shares").json(&req))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn explorer_has_minimal_csp() {
    let (app, _) = app("");
    let r = send(&app, Req::get("/docs/api/explorer")).await;
    let csp = r.headers["content-security-policy"].to_str().unwrap();
    assert!(!csp.contains("wasm-unsafe-eval"));
    let r = send(&app, Req::get("/")).await;
    assert!(
        r.headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("wasm-unsafe-eval")
    );
}
