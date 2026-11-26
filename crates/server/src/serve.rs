//! Connection-level hardening: the accept loop for plain TCP and native TLS.
//!
//! `axum::serve` and `axum-server` do not bound connections or header-read
//! time by default, which allows slowloris-style file-descriptor exhaustion.
//! This loop enforces:
//!
//! * a global cap on open connections (`server.max_connections`);
//! * a per-peer-IP cap (`server.max_connections_per_ip`), exempting
//!   configured trusted proxies, which multiplex many clients;
//! * a TLS handshake timeout and an HTTP/1 header-read timeout, which also
//!   bounds how long an idle keep-alive connection may wait for its next request;
//! * HTTP/2 keep-alive pings and a per-connection stream limit;
//! * graceful shutdown with a bounded drain period.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use ipnet::IpNet;
use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower::ServiceExt;

/// Connection limits (from `[server]` and `[security]`).
#[derive(Debug, Clone)]
pub struct ConnLimits {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub header_read_timeout: Duration,
    pub tls_handshake_timeout: Duration,
    pub trusted_proxies: Vec<IpNet>,
}

#[derive(Debug, Default)]
struct PerIp(Mutex<HashMap<IpAddr, usize>>);

struct IpGuard {
    map: Arc<PerIp>,
    ip: Option<IpAddr>,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        if let Some(ip) = self.ip {
            let mut m = self.map.0.lock();
            if let Some(n) = m.get_mut(&ip) {
                *n -= 1;
                if *n == 0 {
                    m.remove(&ip);
                }
            }
        }
    }
}

impl PerIp {
    fn try_acquire(self: &Arc<Self>, ip: IpAddr, max: usize) -> Option<IpGuard> {
        let mut m = self.0.lock();
        let n = m.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(IpGuard {
            map: Arc::clone(self),
            ip: Some(ip),
        })
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

fn http_builder(limits: &ConnLimits) -> Builder<TokioExecutor> {
    let mut b = Builder::new(TokioExecutor::new());
    b.http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout)
        .keep_alive(true)
        .max_buf_size(64 * 1024);
    b.http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .max_concurrent_streams(64)
        .max_header_list_size(32 * 1024);
    b
}

/// TLS acceptor type (feature `tls`).
#[cfg(feature = "tls")]
pub type Tls = tokio_rustls::TlsAcceptor;
#[cfg(not(feature = "tls"))]
pub type Tls = ();

/// Load a rustls server configuration from PEM files (TLS 1.2 and 1.3, ring provider).
///
/// # Errors
/// Returns a description of the failure (never key material).
#[cfg(feature = "tls")]
pub fn load_tls(cert: &std::path::Path, key: &std::path::Path) -> Result<Tls, String> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|_| "cannot read TLS certificate file".to_owned())?
        .collect::<Result<_, _>>()
        .map_err(|_| "invalid TLS certificate PEM".to_owned())?;
    let key =
        PrivateKeyDer::from_pem_file(key).map_err(|_| "cannot read TLS private key".to_owned())?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| "TLS configuration error".to_owned())?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|_| "certificate and key do not match or are unsupported".to_owned())?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
}

/// Accept connections until `shutdown` resolves, then drain for up to `grace`.
pub async fn run(
    listener: TcpListener,
    app: Router,
    limits: ConnLimits,
    tls: Option<Tls>,
    shutdown: impl Future<Output = ()>,
    grace: Duration,
) {
    let conns = Arc::new(Semaphore::new(limits.max_connections));
    let per_ip = Arc::new(PerIp::default());
    let builder = Arc::new(http_builder(&limits));
    let graceful = GracefulShutdown::new();
    let limits = Arc::new(limits);
    tokio::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    // EMFILE/ENFILE etc.: back off briefly instead of spinning.
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let Ok(conn_permit) = Arc::clone(&conns).try_acquire_owned() else {
            drop(stream); // over the global cap: refuse immediately
            continue;
        };
        let ip = canonical(peer.ip());
        let ip_guard = if limits.trusted_proxies.iter().any(|n| n.contains(&ip)) {
            IpGuard {
                map: Arc::clone(&per_ip),
                ip: None,
            }
        } else {
            match per_ip.try_acquire(ip, limits.max_connections_per_ip) {
                Some(g) => g,
                None => {
                    drop(stream);
                    continue;
                }
            }
        };
        let _ = stream.set_nodelay(true);

        let app = app.clone();
        let service =
            hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                req.extensions_mut().insert(ConnectInfo(peer));
                app.clone().oneshot(req.map(axum::body::Body::new))
            });
        let builder = Arc::clone(&builder);
        let watcher = graceful.watcher();
        let limits = Arc::clone(&limits);
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permits = (conn_permit, ip_guard);
            match tls {
                #[cfg(feature = "tls")]
                Some(acceptor) => {
                    let Ok(Ok(tls_stream)) =
                        tokio::time::timeout(limits.tls_handshake_timeout, acceptor.accept(stream))
                            .await
                    else {
                        return;
                    };
                    let conn =
                        builder.serve_connection_with_upgrades(TokioIo::new(tls_stream), service);
                    let _ = watcher.watch(conn.into_owned()).await;
                }
                #[cfg(not(feature = "tls"))]
                Some(()) => {
                    let _ = (stream, service, watcher, limits);
                }
                None => {
                    let _ = &limits;
                    let conn =
                        builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
                    let _ = watcher.watch(conn.into_owned()).await;
                }
            }
        });
    }

    drop(listener);
    if tokio::time::timeout(grace, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("graceful shutdown timed out; closing remaining connections");
    }
}

/// Convenience for tests: the effective local address of a bound listener.
#[must_use]
pub fn local_addr(l: &TcpListener) -> Option<SocketAddr> {
    l.local_addr().ok()
}
