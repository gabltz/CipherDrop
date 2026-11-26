//! RAM-only mode must not write share data to the filesystem.
//!
//! This test binary runs a single test because it changes the process-wide
//! working directory and `TMPDIR`.

mod common;

use axum::http::StatusCode;
use common::*;

fn snapshot(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p.clone());
            }
            out.push(p);
        }
    }
    out
}

#[tokio::test(flavor = "current_thread")]
async fn ram_only_mode_writes_nothing_to_disk() {
    let work = tempfile::tempdir().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_current_dir(work.path()).unwrap();
    // SAFETY-free: single-threaded test binary with one test.
    unsafe_env_set("TMPDIR", tmp.path());

    let (app, state) = app("");
    for i in 0..50 {
        let (mut req, _) = encrypted_request(&format!("ram-only synthetic {i}"));
        req.max_reads = Some(Some(2));
        let c = create(&app, &req).await;
        assert_eq!(consume(&app, &c.id).await.status, StatusCode::OK);
        if i % 2 == 0 {
            let r = send(
                &app,
                Req::delete(format!("/api/v1/shares/{}", c.id))
                    .header("x-revocation-token", &c.revocation_token),
            )
            .await;
            assert_eq!(r.status, StatusCode::NO_CONTENT);
        }
    }
    state.memory.purge_expired(u64::MAX);
    drop(app);
    drop(state);
    assert!(
        snapshot(work.path()).is_empty(),
        "files created in cwd: {:?}",
        snapshot(work.path())
    );
    assert!(
        snapshot(tmp.path()).is_empty(),
        "files created in TMPDIR: {:?}",
        snapshot(tmp.path())
    );
}

fn unsafe_env_set(k: &str, v: &std::path::Path) {
    // `std::env::set_var` is `unsafe` in edition 2024 because other threads may
    // read the environment concurrently; this test is single-threaded.
    #[allow(unsafe_code)]
    // SAFETY: current_thread runtime, single test in this binary, no other threads.
    unsafe {
        std::env::set_var(k, v);
    }
}
