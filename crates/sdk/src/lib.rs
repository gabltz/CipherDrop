//! # CipherDrop Rust SDK
//!
//! All encryption and decryption happen locally. The server receives only
//! ciphertext; the share key is placed in the URL fragment by this SDK and
//! never transmitted.
//!
//! ```no_run
//! # async fn demo() -> Result<(), cipherdrop_sdk::Error> {
//! use cipherdrop_sdk::{Client, CreateOptions};
//! use secrecy::ExposeSecret;
//!
//! let client = Client::builder("https://paste.example.com")
//!     .api_key(std::env::var("CIPHERDROP_API_KEY").ok())
//!     .build()?;
//! let share = client
//!     .create_secret("example secret", CreateOptions { ttl_seconds: Some(3600), max_reads: Some(1), ..Default::default() })
//!     .await?;
//! println!("{}", share.url.expose_secret());
//!
//! let payload = client.read(share.url.expose_secret(), None).await?;
//! assert_eq!(payload.content, "example secret");
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]

use std::time::Duration;

pub use cipherdrop_protocol as protocol;
use cipherdrop_protocol::ProtocolError;
use cipherdrop_protocol::api::{
    ConfigResponse, ConsumeShareResponse, CreateShareRequest, CreateShareResponse, Problem,
    ShareStatusResponse, StorageBackend,
};
use cipherdrop_protocol::crypto::{
    DEFAULT_PAD_TO, KdfCost, ShareKey, decrypt_payload, encrypt_payload,
};
use cipherdrop_protocol::payload::SecretPayload;
use cipherdrop_protocol::url::{RevocationLink, ShareId, ShareLink};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// SDK errors. Messages never include secrets, keys or plaintext.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid base URL")]
    InvalidBaseUrl,
    #[error(
        "refusing plain-HTTP base URL; use https:// (or allow_insecure_http for local testing)"
    )]
    InsecureBaseUrl,
    #[error("HTTP transport error: {0}")]
    Transport(#[source] reqwest::Error),
    #[error("API error {status}: {}", problem.as_ref().map_or("unexpected response", |p| p.title.as_str()))]
    Api {
        status: u16,
        problem: Option<Problem>,
    },
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("could not read CA certificate")]
    CaCertificate,
}

impl Error {
    /// Machine-readable API error code (e.g. `share_unavailable`), if any.
    #[must_use]
    pub fn api_code(&self) -> Option<&str> {
        match self {
            Self::Api {
                problem: Some(p), ..
            } => Some(&p.code),
            _ => None,
        }
    }
}

/// Builder for [`Client`].
pub struct ClientBuilder {
    base_url: String,
    api_key: Option<SecretString>,
    timeout: Duration,
    allow_insecure_http: bool,
    extra_roots: Vec<reqwest::Certificate>,
    user_agent: String,
}

impl core::fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl ClientBuilder {
    /// API token (`cdt_...`). `None` for anonymous access.
    #[must_use]
    pub fn api_key(mut self, key: Option<String>) -> Self {
        self.api_key = key.filter(|k| !k.is_empty()).map(SecretString::from);
        self
    }

    #[must_use]
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Permit `http://` base URLs. Intended for local development only.
    #[must_use]
    pub fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// Trust an additional CA certificate (PEM) in addition to the system store.
    /// Certificate validation itself cannot be disabled.
    ///
    /// # Errors
    /// [`Error::CaCertificate`] if the PEM cannot be parsed.
    pub fn add_root_certificate_pem(mut self, pem: &[u8]) -> Result<Self, Error> {
        self.extra_roots
            .push(reqwest::Certificate::from_pem(pem).map_err(|_| Error::CaCertificate)?);
        Ok(self)
    }

    #[must_use]
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    /// Build the client.
    ///
    /// # Errors
    /// Fails on invalid base URLs or HTTP client construction errors.
    pub fn build(self) -> Result<Client, Error> {
        let u = url::Url::parse(&self.base_url).map_err(|_| Error::InvalidBaseUrl)?;
        match u.scheme() {
            "https" => {}
            "http" if self.allow_insecure_http => {}
            "http" => return Err(Error::InsecureBaseUrl),
            _ => return Err(Error::InvalidBaseUrl),
        }
        if u.fragment().is_some() || u.query().is_some() {
            return Err(Error::InvalidBaseUrl);
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut b = reqwest::Client::builder()
            .timeout(self.timeout)
            .user_agent(self.user_agent)
            .https_only(!self.allow_insecure_http)
            .redirect(reqwest::redirect::Policy::none())
            .referer(false);
        for c in self.extra_roots {
            b = b.add_root_certificate(c);
        }
        let http = b.build().map_err(Error::Transport)?;
        Ok(Client {
            base_url: self.base_url.trim_end_matches('/').to_owned(),
            api_key: self.api_key,
            http,
        })
    }
}

/// CipherDrop API client.
#[derive(Clone)]
pub struct Client {
    base_url: String,
    api_key: Option<SecretString>,
    http: reqwest::Client,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

/// Options for [`Client::create_secret`].
#[derive(Default)]
pub struct CreateOptions {
    /// Lifetime in seconds; `None` = instance default.
    pub ttl_seconds: Option<u64>,
    /// Request a share that never expires (requires authorization).
    pub never_expire: bool,
    /// Maximum retrievals; `None` = instance default.
    pub max_reads: Option<u32>,
    /// Unlimited retrievals until expiry (if the instance allows it).
    pub unlimited_reads: bool,
    /// Optional password; never sent to the server.
    pub password: Option<SecretString>,
    pub kdf_cost: Option<KdfCost>,
    pub title: Option<String>,
    pub syntax: Option<String>,
    pub storage: Option<StorageBackend>,
    pub idempotency_key: Option<String>,
}

impl core::fmt::Debug for CreateOptions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CreateOptions")
            .field("ttl_seconds", &self.ttl_seconds)
            .field("max_reads", &self.max_reads)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

/// A created share. `url` and `revocation_token` are secrets.
pub struct CreatedShare {
    /// Complete share link **including** the `#v1.<key>` fragment.
    pub url: SecretString,
    pub id: String,
    pub expires_at: Option<String>,
    pub max_reads: Option<u32>,
    pub storage: StorageBackend,
    pub revocation_token: SecretString,
    /// `{base}/revoke/{id}#v1.{token}`; keep it away from recipients.
    pub revocation_url: SecretString,
}

impl core::fmt::Debug for CreatedShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CreatedShare")
            .field("expires_at", &self.expires_at)
            .field("max_reads", &self.max_reads)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Start building a client for `base_url` (e.g. `https://paste.example.com`).
    #[must_use]
    pub fn builder(base_url: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            base_url: base_url.into(),
            api_key: None,
            timeout: Duration::from_secs(30),
            allow_insecure_http: false,
            extra_roots: Vec::new(),
            user_agent: format!("cipherdrop-sdk-rust/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn req(&self, m: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut r = self.http.request(m, format!("{}{path}", self.base_url));
        if let Some(k) = &self.api_key {
            r = r.bearer_auth(k.expose_secret());
        }
        r
    }

    async fn send<T: serde::de::DeserializeOwned>(r: reqwest::RequestBuilder) -> Result<T, Error> {
        let res = r.send().await.map_err(Error::Transport)?;
        let status = res.status();
        if status.is_success() {
            return res.json().await.map_err(Error::Transport);
        }
        let problem = res.json::<Problem>().await.ok();
        Err(Error::Api {
            status: status.as_u16(),
            problem,
        })
    }

    /// Public instance configuration.
    ///
    /// # Errors
    /// Transport or API errors.
    pub async fn config(&self) -> Result<ConfigResponse, Error> {
        Self::send(self.req(reqwest::Method::GET, "/api/v1/config")).await
    }

    /// Encrypt `payload` locally and upload the ciphertext.
    ///
    /// # Errors
    /// Encryption, transport or API errors.
    pub async fn create(
        &self,
        payload: &SecretPayload,
        opts: CreateOptions,
    ) -> Result<CreatedShare, Error> {
        let key = ShareKey::generate()?;
        let pw = opts
            .password
            .as_ref()
            .map(|p| (p.expose_secret(), opts.kdf_cost.unwrap_or_default()));
        let env = encrypt_payload(&key, payload, pw, DEFAULT_PAD_TO)?;
        let mut body = CreateShareRequest::from_envelope(env.to_wire());
        body.ttl_seconds = if opts.never_expire {
            Some(None)
        } else {
            opts.ttl_seconds.map(Some)
        };
        body.max_reads = if opts.unlimited_reads {
            Some(None)
        } else {
            opts.max_reads.map(Some)
        };
        body.storage = opts.storage;
        let mut r = self
            .req(reqwest::Method::POST, "/api/v1/shares")
            .json(&body);
        if let Some(k) = &opts.idempotency_key {
            r = r.header("Idempotency-Key", k);
        }
        let resp: CreateShareResponse = Self::send(r).await?;
        let url = Zeroizing::new(ShareLink::attach_key(&resp.url, &key)?);
        Ok(CreatedShare {
            url: SecretString::from(url.as_str()),
            id: resp.id,
            expires_at: resp.expires_at,
            max_reads: resp.max_reads,
            storage: resp.storage,
            revocation_token: SecretString::from(resp.revocation_token),
            revocation_url: SecretString::from(resp.revocation_url),
        })
    }

    /// Convenience: share plain text.
    ///
    /// # Errors
    /// See [`Client::create`].
    pub async fn create_secret(
        &self,
        text: &str,
        opts: CreateOptions,
    ) -> Result<CreatedShare, Error> {
        let payload = Zeroizing::new(SecretPayload {
            content: text.to_owned(),
            title: opts.title.clone(),
            syntax: opts.syntax.clone(),
        });
        self.create(&payload, opts).await
    }

    /// Consume one retrieval and decrypt locally.
    ///
    /// **Not retried automatically**: a lost response after a successful
    /// consume cannot be recovered.
    ///
    /// # Errors
    /// Malformed link, transport, API or decryption errors.
    pub async fn read(
        &self,
        link: &str,
        password: Option<&str>,
    ) -> Result<Zeroizing<SecretPayload>, Error> {
        let link = ShareLink::parse(link)?;
        if password.is_none() && self.status(&link.share_id).await?.password_protected {
            // Fail before consuming: a retrieval must not be burned without the password.
            return Err(ProtocolError::PasswordRequired.into());
        }
        let consumed = self.consume(&link.share_id).await?;
        let env = consumed.envelope().decode(usize::MAX)?;
        Ok(decrypt_payload(&link.key, &env, password)?)
    }

    /// Raw consume (returns the encrypted envelope).
    ///
    /// # Errors
    /// Transport or API errors.
    pub async fn consume(&self, id: &ShareId) -> Result<ConsumeShareResponse, Error> {
        Self::send(
            self.req(
                reqwest::Method::POST,
                &format!("/api/v1/shares/{id}/consume"),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body("{}"),
        )
        .await
    }

    /// Non-consuming status.
    ///
    /// # Errors
    /// Transport or API errors (`404 share_unavailable` when gone).
    pub async fn status(&self, id: &ShareId) -> Result<ShareStatusResponse, Error> {
        Self::send(self.req(reqwest::Method::GET, &format!("/api/v1/shares/{id}/status"))).await
    }

    /// Revoke using a revocation link (`.../revoke/{id}#v1.{token}`).
    ///
    /// # Errors
    /// Malformed link, transport or API errors.
    pub async fn revoke_with_link(&self, revocation_link: &str) -> Result<(), Error> {
        let l = RevocationLink::parse(revocation_link)?;
        self.revoke(&l.share_id, Some(&l.token)).await
    }

    /// Revoke with a revocation token, or with the client's API key
    /// (`shares:revoke`) when `token` is `None`.
    ///
    /// # Errors
    /// Transport or API errors.
    pub async fn revoke(&self, id: &ShareId, token: Option<&str>) -> Result<(), Error> {
        let mut r = self.req(reqwest::Method::DELETE, &format!("/api/v1/shares/{id}"));
        if let Some(t) = token {
            r = r.header("X-Revocation-Token", t);
        }
        let res = r.send().await.map_err(Error::Transport)?;
        if res.status().is_success() {
            return Ok(());
        }
        let status = res.status().as_u16();
        Err(Error::Api {
            status,
            problem: res.json::<Problem>().await.ok(),
        })
    }
}
