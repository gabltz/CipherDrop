//! Drives the real `cipherdrop` binary against an in-process server.

use std::io::Write;
use std::net::SocketAddr;
use std::process::{Command, Output, Stdio};

use cipherdrop_server::app::build_router;
use cipherdrop_server::config::Config;
use cipherdrop_server::state::AppState;

fn spawn_server() -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let cfg = Config::from_toml_with_env(
                &format!("[server]\npublic_url = \"http://{addr}\"\n[security]\nrequire_https = false\n[auth]\nanonymous_creation = true\n"),
                Vec::new(),
            )
            .unwrap();
            let app = build_router(AppState::new(cfg).unwrap()).into_make_service_with_connect_info::<SocketAddr>();
            tx.send(format!("http://{addr}")).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    rx.recv().unwrap()
}

fn run(server: &str, args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cipherdrop"))
        .args(["--allow-insecure-http", "--server", server])
        .args(args)
        .env_remove("CIPHERDROP_API_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn create_read_status_revoke() {
    let server = spawn_server();

    let out = run(
        &server,
        &["create", "--ttl", "1h", "--once"],
        b"example secret",
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let link = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    assert!(link.starts_with(&format!("{server}/s/")) && link.contains("#v1."));

    let out = run(&server, &["status"], link.as_bytes());
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("remaining_reads:    1"));

    let out = run(&server, &["read"], link.as_bytes());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"example secret");

    // Burned: exit code 3.
    let out = run(&server, &["read"], link.as_bytes());
    assert_eq!(out.status.code(), Some(3));

    // JSON output and revocation via revocation link from stdin.
    let out = run(
        &server,
        &["--json", "create", "--max-reads", "3", "--title", "T"],
        b"multi\nline\n",
    );
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let url = v["url"].as_str().unwrap().to_owned();
    let out = run(&server, &["--json", "read"], url.as_bytes());
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["content"], "multi\nline\n");
    assert_eq!(r["title"], "T");
    let out = run(
        &server,
        &["revoke"],
        v["revocation_url"].as_str().unwrap().as_bytes(),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        run(&server, &["read"], url.as_bytes()).status.code(),
        Some(3)
    );

    // Wrong key → exit 5 (decryption failure); the share is consumed regardless.
    let out = run(&server, &["create", "--max-reads", "2"], b"x");
    let link = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    let (head, _) = link.split_once("#v1.").unwrap();
    let wrong = format!("{head}#v1.{}", "A".repeat(43));
    assert_eq!(
        run(&server, &["read"], wrong.as_bytes()).status.code(),
        Some(5)
    );

    // Password via file.
    let dir = std::env::temp_dir().join(format!("cdcli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pwf = dir.join("pw");
    std::fs::write(&pwf, "synthetic pass\n").unwrap();
    let out = run(
        &server,
        &["create", "--password-file", pwf.to_str().unwrap()],
        b"pw secret",
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let link = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    let out = run(
        &server,
        &["read", "--password-file", pwf.to_str().unwrap()],
        link.as_bytes(),
    );
    assert_eq!(out.stdout, b"pw secret");
    std::fs::remove_dir_all(&dir).unwrap();

    // Link for another server is refused when --server differs.
    let out = run(&server, &["read"], b"https://other.example/s/AAAAAAAAAAAAAAAAAAAAAA#v1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert_eq!(out.status.code(), Some(2));
    // Empty stdin.
    assert_eq!(run(&server, &["create"], b"").status.code(), Some(2));
}
