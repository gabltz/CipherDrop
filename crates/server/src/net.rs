//! Client address resolution and per-IP rate limiting.
//!
//! `X-Forwarded-For` / `X-Forwarded-Proto` are honoured **only** when
//! `security.trust_forwarded_headers` is enabled **and** the TCP peer is in
//! `security.trusted_proxies`. The client address is then the right-most
//! `X-Forwarded-For` entry that is not itself a trusted proxy, so a client
//! cannot forge its address by prepending entries.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;

use axum::http::HeaderMap;
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use ipnet::IpNet;

use crate::config::SecurityConfig;

/// Resolved request origin information, inserted as a request extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientInfo {
    pub ip: IpAddr,
    /// Whether the client connection is known to be HTTPS.
    pub https: bool,
}

fn is_trusted(ip: IpAddr, proxies: &[IpNet]) -> bool {
    let ip = canonical(ip);
    proxies.iter().any(|n| n.contains(&ip))
}

/// Map IPv4-mapped IPv6 addresses to IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Determine the client IP and scheme for a request.
#[must_use]
pub fn resolve_client(
    peer: SocketAddr,
    headers: &HeaderMap,
    sec: &SecurityConfig,
    native_tls: bool,
) -> ClientInfo {
    let peer_ip = canonical(peer.ip());
    if !(sec.trust_forwarded_headers && is_trusted(peer_ip, &sec.trusted_proxies)) {
        return ClientInfo {
            ip: peer_ip,
            https: native_tls,
        };
    }
    // Walk X-Forwarded-For from the right, skipping trusted proxies.
    let mut client = peer_ip;
    let xff: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();
    for entry in xff.iter().rev() {
        match entry.parse::<IpAddr>() {
            Ok(ip) => {
                let ip = canonical(ip);
                client = ip;
                if !is_trusted(ip, &sec.trusted_proxies) {
                    break;
                }
            }
            // Unparseable entry: stop and keep the last trustworthy hop.
            Err(_) => break,
        }
    }
    let proto_https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next_back())
        .is_some_and(|p| p.trim().eq_ignore_ascii_case("https"));
    ClientInfo {
        ip: client,
        https: native_tls || proto_https,
    }
}

/// Rate-limit key: IPv4 address, or IPv6 address truncated to a prefix.
#[must_use]
pub fn rate_key(ip: IpAddr, v6_prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let p = u32::from(v6_prefix.min(128));
            let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            IpAddr::V6(Ipv6Addr::from(bits & mask))
        }
    }
}

/// Keyed per-IP limiters for the two request classes.
#[derive(Debug)]
pub struct IpLimiters {
    pub create: DefaultKeyedRateLimiter<IpAddr>,
    pub read: DefaultKeyedRateLimiter<IpAddr>,
    pub v6_prefix: u8,
}

impl IpLimiters {
    #[must_use]
    pub fn new(create_per_minute: u32, read_per_minute: u32, v6_prefix: u8) -> Self {
        let q = |n: u32| Quota::per_minute(NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN));
        Self {
            create: RateLimiter::keyed(q(create_per_minute)),
            read: RateLimiter::keyed(q(read_per_minute)),
            v6_prefix,
        }
    }

    /// Drop state for idle keys (bounded memory under address churn).
    pub fn cleanup(&self) {
        self.create.retain_recent();
        self.read.retain_recent();
        self.create.shrink_to_fit();
        self.read.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn sec(trust: bool) -> SecurityConfig {
        SecurityConfig {
            trust_forwarded_headers: trust,
            trusted_proxies: vec!["10.0.0.0/8".parse().unwrap()],
            ..SecurityConfig::default()
        }
    }

    fn headers(xff: &str, proto: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(xff).unwrap());
        h.insert("x-forwarded-proto", HeaderValue::from_str(proto).unwrap());
        h
    }

    #[test]
    fn forwarded_headers_ignored_unless_trusted() {
        let peer: SocketAddr = "203.0.113.9:1234".parse().unwrap();
        let c = resolve_client(peer, &headers("1.2.3.4", "https"), &sec(true), false);
        assert_eq!(c.ip, peer.ip(), "untrusted peer cannot set XFF");
        assert!(!c.https, "untrusted peer cannot claim https");
        let proxy: SocketAddr = "10.1.1.1:1234".parse().unwrap();
        let c = resolve_client(proxy, &headers("1.2.3.4", "https"), &sec(false), false);
        assert_eq!(c.ip, proxy.ip(), "trust disabled");
    }

    #[test]
    fn forged_xff_prefix_does_not_win() {
        let proxy: SocketAddr = "10.1.1.1:1234".parse().unwrap();
        // Client 198.51.100.7 forged "6.6.6.6" in front; proxy appended the real address.
        let c = resolve_client(
            proxy,
            &headers("6.6.6.6, 198.51.100.7", "https"),
            &sec(true),
            false,
        );
        assert_eq!(c.ip, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert!(c.https);
        // Chain of trusted proxies is skipped.
        let c = resolve_client(
            proxy,
            &headers("198.51.100.7, 10.2.2.2", "http"),
            &sec(true),
            false,
        );
        assert_eq!(c.ip, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert!(!c.https);
    }

    #[test]
    fn ipv6_prefix_grouping() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        assert_eq!(rate_key(a, 64), rate_key(b, 64));
        assert_ne!(rate_key(a, 128), rate_key(b, 128));
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(rate_key(v4, 64), v4);
    }

    #[test]
    fn mapped_ipv4_is_canonicalized() {
        let peer: SocketAddr = "[::ffff:10.1.1.1]:80".parse().unwrap();
        let c = resolve_client(peer, &headers("198.51.100.7", "https"), &sec(true), false);
        assert_eq!(c.ip, "198.51.100.7".parse::<IpAddr>().unwrap());
    }
}
