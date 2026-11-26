//! SDK against a real server bound to an ephemeral loopback port.

use std::net::SocketAddr;

use cipherdrop_sdk::protocol::url::ShareLink;
use cipherdrop_sdk::{Client, CreateOptions};
use cipherdrop_server::app::build_router;
use cipherdrop_server::config::Config;
use cipherdrop_server::state::AppState;
use secrecy::{ExposeSecret, SecretString};

async fn spawn_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = Config::from_toml_with_env(
        &format!(
            "[server]\npublic_url = \"http://{addr}\"\n[security]\nrequire_https = false\n[auth]\nanonymous_creation = true\n"
        ),
        Vec::new(),
    )
    .unwrap();
    cfg.validate().unwrap();
    let app = build_router(AppState::new(cfg).unwrap())
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn sdk_roundtrip() {
    let base = spawn_server().await;
    assert!(matches!(
        Client::builder(&base).build(),
        Err(cipherdrop_sdk::Error::InsecureBaseUrl)
    ));
    let client = Client::builder(&base)
        .allow_insecure_http(true)
        .build()
        .unwrap();
    let cfg = client.config().await.unwrap();
    assert_eq!(cfg.protocol_versions, vec![1]);

    let share = client
        .create_secret(
            "sdk synthetic secret",
            CreateOptions {
                ttl_seconds: Some(600),
                max_reads: Some(2),
                title: Some("Synthetic".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let url = share.url.expose_secret().to_owned();
    assert!(url.contains("#v1."));
    let link = ShareLink::parse(&url).unwrap();
    let st = client.status(&link.share_id).await.unwrap();
    assert_eq!(st.remaining_reads, Some(2));
    let p = client.read(&url, None).await.unwrap();
    assert_eq!(p.content, "sdk synthetic secret");
    assert_eq!(p.title.as_deref(), Some("Synthetic"));
    client
        .revoke_with_link(share.revocation_url.expose_secret())
        .await
        .unwrap();
    let err = client.read(&url, None).await.unwrap_err();
    assert_eq!(err.api_code(), Some("share_unavailable"));

    // Password-protected.
    let share = client
        .create_secret(
            "pw synthetic",
            CreateOptions {
                password: Some(SecretString::from("synthetic passphrase")),
                kdf_cost: Some(cipherdrop_sdk::protocol::crypto::KdfCost {
                    memory_kib: 19_456,
                    iterations: 2,
                    parallelism: 1,
                }),
                max_reads: Some(3),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let url = share.url.expose_secret().to_owned();
    assert!(client.read(&url, None).await.is_err());
    let err = client.read(&url, Some("wrong")).await.unwrap_err();
    assert_eq!(
        err.api_code(),
        Some("access_denied"),
        "server rejects wrong password"
    );
    let id = ShareLink::parse(&url).unwrap().share_id;
    let st = client.status(&id).await.unwrap();
    assert!(st.access_protected);
    assert_eq!(
        st.remaining_reads,
        Some(3),
        "wrong password consumed nothing"
    );
    assert_eq!(
        client
            .read(&url, Some("synthetic passphrase"))
            .await
            .unwrap()
            .content,
        "pw synthetic"
    );
}
