//! Storage-separation guarantees across restarts.

mod common;

use axum::http::StatusCode;
use cipherdrop_protocol::api::StorageBackend;
use cipherdrop_protocol::encoding::b64_decode;
use common::*;

fn persistent_cfg(db: &std::path::Path, snippet: &str) -> String {
    format!(
        "[storage]\npersistent_enabled = true\nsqlite_path = {:?}\n[shares]\nallow_permanent = true\n{snippet}",
        db.display().to_string()
    )
}

#[tokio::test]
async fn persistent_survives_restart_ephemeral_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("cipherdrop.sqlite3");
    let (tok, snip) = token(&["shares:create", "shares:create:persistent"]);
    let cfg = persistent_cfg(&db, &snip);

    let (persistent_id, ephemeral_id, ephemeral_ct) = {
        let (app, _) = app(&cfg);
        // Persistent requires the dedicated scope: anonymous is refused.
        let (mut p, _) = encrypted_request("persistent synthetic");
        p.storage = Some(StorageBackend::Persistent);
        p.max_reads = Some(Some(2));
        let r = send(&app, Req::post("/api/v1/shares").json(&p)).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        let r = send(&app, Req::post("/api/v1/shares").json(&p).bearer(&tok)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
        assert_eq!(r.json()["storage"], "persistent");
        let pid = r.json()["id"].as_str().unwrap().to_owned();
        // Permanent (no expiry) persistent share.
        let mut perm = p.clone();
        perm.ttl_seconds = Some(None);
        let r = send(&app, Req::post("/api/v1/shares").json(&perm).bearer(&tok)).await;
        assert_eq!(r.status, StatusCode::CREATED);
        assert!(r.json()["expires_at"].is_null());

        let (e, _) = encrypted_request("ephemeral synthetic");
        let ect = b64_decode(&e.ciphertext, "c").unwrap();
        let created = create(&app, &e).await;
        assert_eq!(created.storage, StorageBackend::Memory);
        // Consume once to exercise the transactional counter.
        assert_eq!(consume(&app, &pid).await.json()["remaining_reads"], 1);
        (pid, created.id, ect)
    }; // "restart": state dropped

    // The ephemeral ciphertext never reached the database file.
    let bytes = std::fs::read(&db).unwrap();
    assert!(
        !bytes
            .windows(ephemeral_ct.len())
            .any(|w| w == ephemeral_ct.as_slice())
    );
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let p = entry.unwrap().path();
        let b = std::fs::read(&p).unwrap();
        assert!(
            !b.windows(ephemeral_ct.len())
                .any(|w| w == ephemeral_ct.as_slice()),
            "{}",
            p.display()
        );
    }

    let (app, _) = app(&cfg);
    assert_eq!(
        send(
            &app,
            Req::get(format!("/api/v1/shares/{ephemeral_id}/status"))
        )
        .await
        .status,
        StatusCode::NOT_FOUND,
        "ephemeral shares must not survive a restart"
    );
    let r = consume(&app, &persistent_id).await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "persistent share survives restart"
    );
    assert_eq!(r.json()["remaining_reads"], 0);
    assert_eq!(
        consume(&app, &persistent_id).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn persistent_one_time_is_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("cd.sqlite3");
    let (tok, snip) = token(&["shares:create", "shares:create:persistent"]);
    let (app, _) = app(&persistent_cfg(&db, &snip));
    let (mut p, _) = encrypted_request("persistent race");
    p.storage = Some(StorageBackend::Persistent);
    let r = send(&app, Req::post("/api/v1/shares").json(&p).bearer(&tok)).await;
    let id = std::sync::Arc::new(r.json()["id"].as_str().unwrap().to_owned());
    let mut tasks = Vec::new();
    for _ in 0..100 {
        let (app, id) = (app.clone(), std::sync::Arc::clone(&id));
        tasks.push(tokio::spawn(async move { consume(&app, &id).await.status }));
    }
    let mut ok = 0;
    for t in tasks {
        if t.await.unwrap() == StatusCode::OK {
            ok += 1;
        }
    }
    assert_eq!(ok, 1);
}

#[tokio::test]
async fn admin_tokens_persist_in_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("cd.sqlite3");
    let (admin, snip) = token(&["admin:manage"]);
    let cfg = format!(
        "[storage]\nsqlite_path = {:?}\n{snip}",
        db.display().to_string()
    );
    let new_token = {
        let (app, _) = app(&cfg);
        let body = serde_json::json!({"name": "persisted", "scopes": ["shares:create"]});
        let r = send(
            &app,
            Req::post("/api/v1/admin/tokens").json(&body).bearer(&admin),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED);
        r.json()["token"].as_str().unwrap().to_owned()
    };
    // The secret itself is not in the database.
    let bytes = std::fs::read(&db).unwrap();
    let secret = &new_token[17..];
    assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
    let (app, _) = app(&cfg);
    let (req, _) = encrypted_request("x");
    let r = send(
        &app,
        Req::post("/api/v1/shares").json(&req).bearer(&new_token),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
}
