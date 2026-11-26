//! Shared helpers for server integration tests. Only synthetic secrets are used.

#![allow(dead_code)]

use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use cipherdrop_protocol::api::{CreateShareRequest, CreateShareResponse};
use cipherdrop_protocol::crypto::{ShareKey, encrypt_payload};
use cipherdrop_protocol::payload::SecretPayload;
use cipherdrop_server::app::build_router;
use cipherdrop_server::config::Config;
use cipherdrop_server::state::AppState;
use http_body_util::BodyExt;

pub const BASE_CONFIG: &str = r#"
[server]
public_url = "https://paste.example.test"

[auth]
anonymous_creation = true
anonymous_retrieval = true

[rate_limit]
create_per_minute = 1000
read_per_minute = 100000
"#;

pub fn config(extra: &str) -> Config {
    // Later keys in `extra` override BASE_CONFIG through TOML table merging.
    let merged = merge_toml(BASE_CONFIG, extra);
    let c = Config::from_toml_with_env(&merged, Vec::new()).expect("parse config");
    c.validate().expect("valid config");
    c
}

fn merge_toml(a: &str, b: &str) -> String {
    let mut ta: toml::Table = toml::from_str(a).unwrap();
    let tb: toml::Table = toml::from_str(b).unwrap();
    fn merge(dst: &mut toml::Table, src: toml::Table) {
        for (k, v) in src {
            match (dst.get_mut(&k), v) {
                (Some(toml::Value::Table(d)), toml::Value::Table(s)) => merge(d, s),
                (_, v) => {
                    dst.insert(k, v);
                }
            }
        }
    }
    merge(&mut ta, tb);
    toml::to_string(&ta).unwrap()
}

pub fn app_with(cfg: Config) -> (Router, AppState) {
    let state = AppState::new(cfg).expect("state");
    (build_router(state.clone()), state)
}

pub fn app(extra: &str) -> (Router, AppState) {
    app_with(config(extra))
}

pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    pub fn code(&self) -> String {
        self.json()["code"].as_str().unwrap_or_default().to_owned()
    }
}

pub struct Req {
    pub method: Method,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub peer: SocketAddr,
}

impl Req {
    pub fn new(method: Method, uri: impl Into<String>) -> Self {
        Self {
            method,
            uri: uri.into(),
            headers: Vec::new(),
            body: Vec::new(),
            peer: "192.0.2.10:40000".parse().unwrap(),
        }
    }
    pub fn get(uri: impl Into<String>) -> Self {
        Self::new(Method::GET, uri)
    }
    pub fn post(uri: impl Into<String>) -> Self {
        Self::new(Method::POST, uri)
    }
    pub fn delete(uri: impl Into<String>) -> Self {
        Self::new(Method::DELETE, uri)
    }
    pub fn header(mut self, k: &str, v: impl Into<String>) -> Self {
        self.headers.push((k.to_owned(), v.into()));
        self
    }
    pub fn json(mut self, v: &impl serde::Serialize) -> Self {
        self.body = serde_json::to_vec(v).unwrap();
        self.header("content-type", "application/json")
    }
    pub fn raw_json(mut self, s: &str) -> Self {
        self.body = s.as_bytes().to_vec();
        self.header("content-type", "application/json")
    }
    pub fn bearer(self, token: &str) -> Self {
        self.header("authorization", format!("Bearer {token}"))
    }
    pub fn peer(mut self, p: &str) -> Self {
        self.peer = p.parse().unwrap();
        self
    }
}

pub async fn send(app: &Router, r: Req) -> Resp {
    use tower::ServiceExt;
    let mut b = Request::builder().method(r.method).uri(r.uri);
    for (k, v) in r.headers {
        b = b.header(k, v);
    }
    let mut req = b.body(Body::from(r.body)).unwrap();
    req.extensions_mut().insert(ConnectInfo(r.peer));
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    Resp {
        status,
        headers,
        body,
    }
}

/// Encrypt a synthetic payload locally, exactly like a real client.
pub fn encrypted_request(content: &str) -> (CreateShareRequest, ShareKey) {
    let key = ShareKey::generate().unwrap();
    let env = encrypt_payload(&key, &SecretPayload::text(content), None, 0).unwrap();
    (CreateShareRequest::from_envelope(env.to_wire()), key)
}

pub async fn create(app: &Router, req: &CreateShareRequest) -> CreateShareResponse {
    let r = send(app, Req::post("/api/v1/shares").json(req)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.text());
    serde_json::from_slice(&r.body).unwrap()
}

pub async fn consume(app: &Router, id: &str) -> Resp {
    send(
        app,
        Req::post(format!("/api/v1/shares/{id}/consume")).raw_json("{}"),
    )
    .await
}

/// Generate an API token and its config snippet values.
pub fn token(scopes: &[&str]) -> (String, String) {
    let g = cipherdrop_server::auth::generate_token().unwrap();
    let snippet = format!(
        "[[auth.tokens]]\nid = \"{}\"\nname = \"test\"\nsha256 = \"{}\"\nscopes = [{}]\n",
        g.id,
        hex::encode(g.verifier.0),
        scopes
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    (g.token.to_string(), snippet)
}
