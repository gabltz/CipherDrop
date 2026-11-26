//! Logs must never contain share ids, URLs, tokens, ciphertext, keys or IPs.
//! Runs with the most verbose log level to maximize exposure.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use cipherdrop_protocol::url::ShareLink;
use common::*;

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn no_sensitive_data_in_logs() {
    let buf = Buf::default();
    let w = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .json()
        .with_writer(move || w.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (admin, snip) = token(&["admin:manage", "shares:create", "shares:revoke"]);
    let (app, _) = app(&snip);
    let (req, key) = encrypted_request("LOG-CANARY-PLAINTEXT");
    let r = send(
        &app,
        Req::post("/api/v1/shares")
            .json(&req)
            .bearer(&admin)
            .peer("198.51.100.77:5555"),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let created: cipherdrop_protocol::api::CreateShareResponse =
        serde_json::from_slice(&r.body).unwrap();
    let link = ShareLink::attach_key(&created.url, &key).unwrap();
    consume(&app, &created.id).await;
    consume(&app, &created.id).await; // 404 path
    send(&app, Req::get(format!("/s/{}", created.id))).await;
    send(
        &app,
        Req::delete(format!("/api/v1/shares/{}", created.id))
            .header("x-revocation-token", &created.revocation_token),
    )
    .await;
    let body = serde_json::json!({"name": "x", "scopes": ["shares:create"]});
    let t = send(
        &app,
        Req::post("/api/v1/admin/tokens").json(&body).bearer(&admin),
    )
    .await;
    let new_token = t.json()["token"].as_str().unwrap().to_owned();
    send(
        &app,
        Req::post("/api/v1/shares")
            .raw_json("{ broken json LOG-CANARY-BODY")
            .bearer(&admin),
    )
    .await;
    send(
        &app,
        Req::get("/api/v1/config")
            .bearer("cdt_aaaaaaaaaaaa_LOG-CANARY-BAD-TOKEN-AAAAAAAAAAAAAAAAAAAAAAAAA"),
    )
    .await;

    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("\"route\""),
        "request logging is active: {logs}"
    );
    let forbidden = [
        created.id.as_str(),
        created.url.as_str(),
        link.as_str(),
        created.revocation_token.as_str(),
        key.to_b64().as_str(),
        req.ciphertext.as_str(),
        &req.ciphertext[..20],
        &admin[17..],
        &new_token[17..],
        "LOG-CANARY",
        "198.51.100.77",
        "authorization",
        "Bearer",
    ]
    .map(str::to_owned);
    for f in &forbidden {
        assert!(!logs.contains(f.as_str()), "log leaked {f:?}:\n{logs}");
    }
}
