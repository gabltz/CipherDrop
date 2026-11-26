//! `cipherdrop`: command-line client.
//!
//! Secrets and capability links are read from **stdin** or a hidden TTY
//! prompt, never from command-line arguments (which leak into shell history
//! and `ps`). Passwords come from a hidden prompt or a file.
//!
//! Exit codes:
//! 0 success · 1 general error · 2 usage/configuration · 3 share unavailable ·
//! 4 authentication/authorization · 5 decryption failed (wrong key/password or
//! tampered) · 6 rate limited / capacity / overloaded · 7 network/TLS error

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use cipherdrop_sdk::protocol::ProtocolError;
use cipherdrop_sdk::protocol::api::StorageBackend;
use cipherdrop_sdk::protocol::url::{RevocationLink, ShareId, ShareLink};
use cipherdrop_sdk::{Client, CreateOptions, Error};
use clap::{Args, Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "cipherdrop",
    version,
    about = "End-to-end encrypted secret sharing (CipherDrop client)"
)]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Args)]
struct Global {
    /// Server base URL. For read/status/revoke the URL embedded in the link is used when omitted.
    #[arg(long, env = "CIPHERDROP_SERVER", global = true)]
    server: Option<String>,
    /// File containing an API token. Alternatively set CIPHERDROP_API_KEY.
    #[arg(long, global = true)]
    api_key_file: Option<PathBuf>,
    /// Additional trusted CA certificate (PEM). Certificate validation cannot be disabled.
    #[arg(long, env = "CIPHERDROP_CA_CERT", global = true)]
    ca_cert: Option<PathBuf>,
    /// Request timeout in seconds.
    #[arg(long, default_value_t = 30, global = true)]
    timeout: u64,
    /// Allow http:// servers (local development only).
    #[arg(long, global = true)]
    allow_insecure_http: bool,
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Encrypt stdin locally and create a share. Prints the share link.
    Create(CreateArgs),
    /// Read a share link from stdin (or a hidden prompt), consume it and print the secret.
    Read(ReadArgs),
    /// Read a share link from stdin and show its status without consuming it.
    Status,
    /// Revoke a share. Reads a revocation link from stdin, or use --id with an API token holding shares:revoke.
    Revoke(RevokeArgs),
    /// Show the server's public configuration.
    Config,
}

#[derive(Args)]
struct CreateArgs {
    /// Lifetime, e.g. 10m, 1h, 7d (default: server default).
    #[arg(long, value_parser = parse_duration)]
    ttl: Option<Duration>,
    /// One-time share (max reads = 1).
    #[arg(long, conflicts_with_all = ["max_reads", "unlimited_reads"])]
    once: bool,
    /// Maximum number of retrievals.
    #[arg(long)]
    max_reads: Option<u32>,
    /// Unlimited retrievals until expiry (if allowed by the server).
    #[arg(long)]
    unlimited_reads: bool,
    /// Never expire (requires shares:create:persistent and server support).
    #[arg(long, conflicts_with = "ttl")]
    never_expire: bool,
    /// Store in the server's persistent backend (requires authorization).
    #[arg(long)]
    persistent: bool,
    /// Protect with an additional password (prompted, never sent to the server).
    #[arg(long)]
    password: bool,
    /// Read the additional password from a file instead of prompting.
    #[arg(long, conflicts_with = "password")]
    password_file: Option<PathBuf>,
    /// Optional title (encrypted).
    #[arg(long)]
    title: Option<String>,
    /// Syntax highlighting hint, e.g. rust, json, yaml (encrypted).
    #[arg(long)]
    syntax: Option<String>,
    /// Idempotency key for safe retries of creation.
    #[arg(long)]
    idempotency_key: Option<String>,
}

#[derive(Args)]
struct ReadArgs {
    /// Prompt for the share password.
    #[arg(long)]
    password: bool,
    /// Read the share password from a file.
    #[arg(long, conflicts_with = "password")]
    password_file: Option<PathBuf>,
}

#[derive(Args)]
struct RevokeArgs {
    /// Share id to revoke using the API token (shares:revoke) instead of a revocation link.
    #[arg(long)]
    id: Option<String>,
}

/// Parse `90`, `90s`, `10m`, `1h`, `7d` (a single number with an optional unit).
fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, mult) = match s.char_indices().last() {
        Some((i, 's')) => (&s[..i], 1),
        Some((i, 'm')) => (&s[..i], 60),
        Some((i, 'h')) => (&s[..i], 3600),
        Some((i, 'd')) => (&s[..i], 86_400),
        _ => (s, 1),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration {s:?}; use e.g. 90s, 10m, 1h, 7d"))?;
    n.checked_mul(mult)
        .filter(|v| *v > 0)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("invalid duration {s:?}"))
}

#[derive(Debug)]
struct Fail(u8, String);

impl From<Error> for Fail {
    fn from(e: Error) -> Self {
        let code = match &e {
            Error::Api { status: 404, .. } => 3,
            Error::Api {
                status: 401 | 403, ..
            } => 4,
            Error::Api {
                status: 429 | 503 | 507,
                ..
            } => 6,
            Error::Api { .. } => 1,
            Error::Protocol(ProtocolError::Decryption | ProtocolError::PasswordRequired) => 5,
            Error::Protocol(ProtocolError::MalformedUrl) => 2,
            Error::Protocol(_) => 1,
            Error::Transport(_) | Error::CaCertificate => 7,
            Error::InvalidBaseUrl | Error::InsecureBaseUrl => 2,
        };
        let msg = match &e {
            Error::Api {
                problem: Some(p), ..
            } => {
                format!(
                    "{} ({}){}",
                    p.title,
                    p.code,
                    p.detail
                        .as_ref()
                        .map(|d| format!(": {d}"))
                        .unwrap_or_default()
                )
            }
            Error::Protocol(ProtocolError::PasswordRequired) => {
                "this share is password protected; use --password".into()
            }
            other => other.to_string(),
        };
        Self(code, msg)
    }
}

fn usage(msg: impl Into<String>) -> Fail {
    Fail(2, msg.into())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    match rt.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail(code, msg)) => {
            eprintln!("error: {msg}");
            ExitCode::from(code)
        }
    }
}

fn api_key(g: &Global) -> Result<Option<String>, Fail> {
    if let Some(p) = &g.api_key_file {
        let s = Zeroizing::new(
            std::fs::read_to_string(p).map_err(|_| usage("cannot read --api-key-file"))?,
        );
        return Ok(Some(s.trim().to_owned()));
    }
    Ok(std::env::var("CIPHERDROP_API_KEY")
        .ok()
        .filter(|s| !s.is_empty()))
}

fn client(g: &Global, base: &str) -> Result<Client, Fail> {
    let mut b = Client::builder(base)
        .api_key(api_key(g)?)
        .timeout(Duration::from_secs(g.timeout))
        .allow_insecure_http(g.allow_insecure_http)
        .user_agent(format!("cipherdrop-cli/{}", env!("CARGO_PKG_VERSION")));
    if let Some(p) = &g.ca_cert {
        let pem = std::fs::read(p).map_err(|_| usage("cannot read --ca-cert"))?;
        b = b.add_root_certificate_pem(&pem)?;
    }
    Ok(b.build()?)
}

/// Choose the server for a link-based command, refusing silent redirection.
fn server_for(g: &Global, link_base: Option<&str>) -> Result<String, Fail> {
    match (g.server.as_deref(), link_base) {
        (Some(s), Some(l)) if s.trim_end_matches('/') != l.trim_end_matches('/') => Err(usage(
            "the link points to a different server than --server/CIPHERDROP_SERVER; refusing to send it elsewhere",
        )),
        (_, Some(l)) => Ok(l.to_owned()),
        (Some(s), None) => Ok(s.to_owned()),
        (None, None) => Err(usage(
            "short-form link given; specify --server or CIPHERDROP_SERVER",
        )),
    }
}

/// Read one capability line from stdin, or prompt without echo on a TTY.
fn read_capability(prompt: &str) -> Result<Zeroizing<String>, Fail> {
    let s = if std::io::stdin().is_terminal() {
        Zeroizing::new(
            rpassword::prompt_password(prompt).map_err(|_| usage("cannot read from terminal"))?,
        )
    } else {
        let mut buf = Zeroizing::new(String::new());
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|_| usage("cannot read stdin"))?;
        buf
    };
    let line = s
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_default();
    if line.is_empty() {
        return Err(usage("no link provided on stdin"));
    }
    Ok(Zeroizing::new(line.to_owned()))
}

fn read_password(
    prompt_flag: bool,
    file: Option<&PathBuf>,
    confirm: bool,
) -> Result<Option<SecretString>, Fail> {
    if let Some(f) = file {
        let s = Zeroizing::new(
            std::fs::read_to_string(f).map_err(|_| usage("cannot read password file"))?,
        );
        let p = s.trim_end_matches(['\r', '\n']);
        if p.is_empty() {
            return Err(usage("password file is empty"));
        }
        return Ok(Some(SecretString::from(p)));
    }
    if !prompt_flag {
        return Ok(None);
    }
    let p = Zeroizing::new(
        rpassword::prompt_password("Share password: ")
            .map_err(|_| usage("cannot read password from terminal"))?,
    );
    if p.is_empty() {
        return Err(usage("empty password"));
    }
    if confirm {
        let p2 = Zeroizing::new(
            rpassword::prompt_password("Repeat password: ")
                .map_err(|_| usage("cannot read password"))?,
        );
        if *p != *p2 {
            return Err(usage("passwords do not match"));
        }
    }
    Ok(Some(SecretString::from(p.as_str())))
}

async fn run(cli: Cli) -> Result<(), Fail> {
    let g = &cli.global;
    match cli.command {
        Cmd::Create(a) => create(g, a).await,
        Cmd::Read(a) => {
            let line = read_capability("Share link: ")?;
            let link = ShareLink::parse(&line).map_err(|_| usage("malformed share link"))?;
            let base = server_for(g, link.base_url.as_deref())?;
            let pw = read_password(a.password, a.password_file.as_ref(), false)?;
            let payload = client(g, &base)?
                .read(&line, pw.as_ref().map(|p| p.expose_secret()))
                .await?;
            let mut out = std::io::stdout().lock();
            if g.json {
                let v = Zeroizing::new(
                    serde_json::to_string(&serde_json::json!({
                        "content": payload.content,
                        "title": payload.title,
                        "syntax": payload.syntax,
                    }))
                    .map_err(|_| Fail(1, "serialization failed".into()))?,
                );
                writeln!(out, "{}", v.as_str()).map_err(|_| Fail(1, "write failed".into()))?;
            } else {
                if let Some(t) = &payload.title {
                    eprintln!("# {t}");
                }
                out.write_all(payload.content.as_bytes())
                    .map_err(|_| Fail(1, "write failed".into()))?;
                if std::io::stdout().is_terminal() && !payload.content.ends_with('\n') {
                    let _ = writeln!(out);
                }
            }
            Ok(())
        }
        Cmd::Status => {
            let line = read_capability("Share link: ")?;
            let (base, id) = match ShareLink::parse(&line) {
                Ok(l) => (server_for(g, l.base_url.as_deref())?, l.share_id),
                Err(_) => {
                    let id = ShareId::parse(line.trim())
                        .map_err(|_| usage("expected a share link or share id"))?;
                    (server_for(g, None)?, id)
                }
            };
            match client(g, &base)?.status(&id).await {
                Ok(s) => {
                    if g.json {
                        println!("{}", serde_json::to_string(&s).unwrap_or_default());
                    } else {
                        println!("available");
                        println!(
                            "expires_at:         {}",
                            s.expires_at.as_deref().unwrap_or("never")
                        );
                        println!(
                            "remaining_reads:    {}",
                            s.remaining_reads
                                .map_or_else(|| "unlimited".into(), |n| n.to_string())
                        );
                        println!("password_protected: {}", s.password_protected);
                    }
                    Ok(())
                }
                Err(e) => {
                    if g.json && e.api_code() == Some("share_unavailable") {
                        println!("{{\"available\":false}}");
                    }
                    Err(e.into())
                }
            }
        }
        Cmd::Revoke(a) => {
            if let Some(id) = a.id {
                let id = ShareId::parse(&id).map_err(|_| usage("malformed share id"))?;
                let base = server_for(g, None)?;
                client(g, &base)?.revoke(&id, None).await?;
            } else {
                let line = read_capability("Revocation link: ")?;
                let l =
                    RevocationLink::parse(&line).map_err(|_| usage("malformed revocation link"))?;
                let base = server_for(g, l.base_url.as_deref())?;
                client(g, &base)?.revoke_with_link(&line).await?;
            }
            if g.json {
                println!("{{\"revoked\":true}}");
            } else {
                eprintln!("revoked");
            }
            Ok(())
        }
        Cmd::Config => {
            let base = server_for(g, None)?;
            let c = client(g, &base)?.config().await?;
            println!("{}", serde_json::to_string_pretty(&c).unwrap_or_default());
            Ok(())
        }
    }
}

async fn create(g: &Global, a: CreateArgs) -> Result<(), Fail> {
    let base = server_for(g, None)?;
    let mut content = Zeroizing::new(String::new());
    if std::io::stdin().is_terminal() {
        eprintln!("Enter the secret, then press Ctrl-D on an empty line:");
    }
    std::io::stdin()
        .read_to_string(&mut content)
        .map_err(|_| usage("stdin is not valid UTF-8"))?;
    if content.is_empty() {
        return Err(usage("nothing to share: stdin was empty"));
    }
    let password = read_password(a.password, a.password_file.as_ref(), true)?;
    let max_reads = if a.once { Some(1) } else { a.max_reads };
    let opts = CreateOptions {
        ttl_seconds: a.ttl.map(|d| d.as_secs()),
        never_expire: a.never_expire,
        max_reads,
        unlimited_reads: a.unlimited_reads,
        password,
        kdf_cost: None,
        title: a.title,
        syntax: a.syntax,
        storage: a.persistent.then_some(StorageBackend::Persistent),
        idempotency_key: a.idempotency_key,
    };
    let share = client(g, &base)?.create_secret(&content, opts).await?;
    if g.json {
        let v = Zeroizing::new(
            serde_json::to_string(&serde_json::json!({
                "url": share.url.expose_secret(),
                "id": share.id,
                "expires_at": share.expires_at,
                "max_reads": share.max_reads,
                "storage": share.storage,
                "revocation_url": share.revocation_url.expose_secret(),
                "revocation_token": share.revocation_token.expose_secret(),
            }))
            .map_err(|_| Fail(1, "serialization failed".into()))?,
        );
        println!("{}", v.as_str());
    } else {
        println!("{}", share.url.expose_secret());
        eprintln!(
            "expires:    {}",
            share.expires_at.as_deref().unwrap_or("never")
        );
        eprintln!(
            "max reads:  {}",
            share
                .max_reads
                .map_or_else(|| "unlimited".into(), |n| n.to_string())
        );
        eprintln!("revoke:     {}", share.revocation_url.expose_secret());
        eprintln!(
            "Anyone with the complete link can decrypt the secret. Keep the revoke link private."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_duration;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap().as_secs(), 90);
        assert_eq!(parse_duration("10m").unwrap().as_secs(), 600);
        assert_eq!(parse_duration("1h").unwrap().as_secs(), 3600);
        assert_eq!(parse_duration("7d").unwrap().as_secs(), 604_800);
        for bad in ["", "0", "h", "1x", "-1h", "1.5h", "99999999999999999d"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }
}
