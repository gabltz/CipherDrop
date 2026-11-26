//! Connection-level hardening of the accept loop (real sockets).

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use cipherdrop_server::app::build_router;
use cipherdrop_server::serve::{ConnLimits, run};
use cipherdrop_server::state::AppState;

fn get_healthz(addr: std::net::SocketAddr) -> bool {
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return false;
    };
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    if s.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 16];
    matches!(s.read(&mut buf), Ok(n) if buf[..n].starts_with(b"HTTP/1.1 200"))
}

fn closed(s: &mut TcpStream) -> bool {
    s.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut b = [0u8; 1];
    // 408/EOF/reset all count as "the server dropped the connection".
    !matches!(s.read(&mut b), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slowloris_connections_are_reaped_and_capped_per_ip() {
    let state = AppState::new(common::config("")).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let limits = ConnLimits {
        max_connections: 1000,
        max_connections_per_ip: 20,
        header_read_timeout: Duration::from_secs(1),
        tls_handshake_timeout: Duration::from_secs(1),
        trusted_proxies: Vec::new(),
    };
    tokio::spawn(run(
        listener,
        build_router(state),
        limits,
        None,
        std::future::pending(),
        Duration::from_secs(1),
    ));

    let result = tokio::task::spawn_blocking(move || {
        // 19 half-open connections from one IP (cap is 20): one slot left.
        let mut slow: Vec<TcpStream> = (0..19)
            .map(|_| {
                let mut s = TcpStream::connect(addr).unwrap();
                s.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
                    .unwrap();
                s
            })
            .collect();
        std::thread::sleep(Duration::from_millis(200));
        assert!(get_healthz(addr), "one connection slot remains usable");
        // Exceed the per-IP cap: extra connections are refused/closed immediately.
        let mut extra: Vec<TcpStream> = (0..5)
            .filter_map(|_| TcpStream::connect(addr).ok())
            .collect();
        std::thread::sleep(Duration::from_millis(300));
        // 19 slow + 1 free slot = cap of 20: exactly one extra fits, the rest are dropped.
        let dropped = extra.iter_mut().map(closed).filter(|c| *c).count();
        assert!(
            dropped >= 4,
            "connections beyond the per-IP cap are dropped ({dropped}/5)"
        );
        // Header read timeout reaps the half-open connections.
        std::thread::sleep(Duration::from_millis(1500));
        assert!(
            slow.iter_mut().all(closed),
            "half-open connections reaped by header timeout"
        );
        // Idle keep-alive connection is also closed by the same timer.
        let mut ka = TcpStream::connect(addr).unwrap();
        ka.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut buf = [0u8; 512];
        let _ = ka.read(&mut buf);
        std::thread::sleep(Duration::from_millis(1600));
        assert!(closed(&mut ka), "idle keep-alive connection closed");
        assert!(get_healthz(addr), "server healthy after attack");
    })
    .await;
    result.unwrap();
}
