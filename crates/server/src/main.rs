//! `cipherdrop-server` executable.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use cipherdrop_protocol::api::Scope;
use cipherdrop_server::app::build_router;
use cipherdrop_server::auth::generate_token;
use cipherdrop_server::config::{Config, LogFormat};
use cipherdrop_server::state::AppState;
use cipherdrop_server::{hardening, maintenance_loop, serve};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "cipherdrop-server",
    version,
    about = "CipherDrop zero-knowledge secret sharing server"
)]
struct Cli {
    /// Path to the TOML configuration file. Environment variables of the form
    /// CIPHERDROP__SECTION__KEY override file values.
    #[arg(short, long, env = "CIPHERDROP_CONFIG", global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the server (default).
    Serve,
    /// Validate the configuration and exit.
    CheckConfig,
    /// Print the OpenAPI document and exit.
    Openapi,
    /// Probe a local /healthz endpoint over plain HTTP (for container HEALTHCHECK).
    Healthcheck {
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: String,
    },
    /// API token utilities.
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
}

#[derive(Subcommand, Debug)]
enum TokenCommand {
    /// Generate a token and print it with a configuration snippet. The token
    /// is printed once; only its SHA-256 verifier belongs in the configuration.
    Generate {
        #[arg(long)]
        name: String,
        /// Scope to grant (repeatable): shares:create, shares:create:persistent,
        /// shares:consume, shares:revoke, admin:metrics, admin:manage.
        #[arg(long = "scope", required = true)]
        scopes: Vec<String>,
    },
}

fn init_logging(cfg: &Config) {
    // Logging configuration comes only from the config file, never RUST_LOG,
    // so that debug logging cannot be enabled by an inherited environment.
    let filter = EnvFilter::new(format!(
        "warn,cipherdrop_server={lvl},cipherdrop_storage={lvl}",
        lvl = cfg.logging.level
    ));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    match cfg.logging.format {
        LogFormat::Json => builder.json().flatten_event(true).init(),
        LogFormat::Text => builder.init(),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Token {
            command: TokenCommand::Generate { name, scopes },
        } => token_generate(&name, &scopes),
        Command::Healthcheck { addr } => healthcheck(&addr),
        Command::CheckConfig => match load(cli.config.as_deref()) {
            Ok(_) => {
                println!("configuration OK");
                ExitCode::SUCCESS
            }
            Err(code) => code,
        },
        Command::Openapi => match load(cli.config.as_deref()) {
            Ok(cfg) => {
                println!("{}", cipherdrop_server::openapi::render(cfg.public_base()));
                ExitCode::SUCCESS
            }
            Err(code) => code,
        },
        Command::Serve => {
            let cfg = match load(cli.config.as_deref()) {
                Ok(c) => c,
                Err(code) => return code,
            };
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("error: cannot start runtime: {e}");
                    return ExitCode::from(1);
                }
            };
            rt.block_on(serve(cfg))
        }
    }
}

fn load(path: Option<&std::path::Path>) -> Result<Config, ExitCode> {
    let cfg = Config::load(path).map_err(|e| {
        eprintln!("error: {e}");
        ExitCode::from(2)
    })?;
    cfg.validate().map_err(|e| {
        eprintln!("error: {e}");
        ExitCode::from(2)
    })?;
    Ok(cfg)
}

fn healthcheck(addr: &str) -> ExitCode {
    use std::io::{Read as _, Write as _};
    let probe = || -> std::io::Result<bool> {
        let sock: SocketAddr = addr
            .parse()
            .map_err(|_| std::io::Error::other("invalid address"))?;
        let mut s = std::net::TcpStream::connect_timeout(&sock, Duration::from_secs(3))?;
        s.set_read_timeout(Some(Duration::from_secs(3)))?;
        write!(
            s,
            "GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
        )?;
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf)?;
        Ok(buf[..n].starts_with(b"HTTP/1.1 200"))
    };
    match probe() {
        Ok(true) => ExitCode::SUCCESS,
        _ => ExitCode::from(1),
    }
}

fn token_generate(name: &str, scopes: &[String]) -> ExitCode {
    for s in scopes {
        if Scope::parse(s).is_none() {
            eprintln!("error: unknown scope {s:?}");
            return ExitCode::from(2);
        }
    }
    let Ok(g) = generate_token() else {
        eprintln!("error: random number generator unavailable");
        return ExitCode::from(1);
    };
    let scopes_toml = scopes
        .iter()
        .map(|s| format!("{s:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("# Token (shown once; store it in your secret manager):");
    println!("# {}", g.token.as_str());
    println!();
    println!("[[auth.tokens]]");
    println!("id = {:?}", g.id);
    println!("name = {name:?}");
    println!("sha256 = {:?}", hex::encode(g.verifier.0));
    println!("scopes = [{scopes_toml}]");
    ExitCode::SUCCESS
}

async fn serve(cfg: Config) -> ExitCode {
    init_logging(&cfg);
    match hardening::apply(&cfg.security) {
        Ok(r) => tracing::info!(
            core_dumps_disabled = r.core_dumps_disabled,
            non_dumpable = r.non_dumpable,
            memory_locked = r.memory_locked,
            "process hardening applied"
        ),
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(1);
        }
    }
    let listen = cfg.server.listen;
    let grace = Duration::from_secs(cfg.server.shutdown_grace_seconds);
    let limits = serve::ConnLimits {
        max_connections: cfg.server.max_connections,
        max_connections_per_ip: cfg.server.max_connections_per_ip,
        header_read_timeout: Duration::from_secs(cfg.server.header_read_timeout_seconds),
        tls_handshake_timeout: Duration::from_secs(10),
        trusted_proxies: if cfg.security.trust_forwarded_headers {
            cfg.security.trusted_proxies.clone()
        } else {
            Vec::new()
        },
    };
    let tls = match &cfg.server.tls {
        None => None,
        #[cfg(feature = "tls")]
        Some(t) => match serve::load_tls(&t.cert_path, &t.key_path) {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::error!("{e}");
                return ExitCode::from(1);
            }
        },
        #[cfg(not(feature = "tls"))]
        Some(_) => {
            tracing::error!("TLS support is not compiled into this binary");
            return ExitCode::from(1);
        }
    };
    let state = match AppState::new(cfg) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::from(1);
        }
    };
    tokio::spawn(maintenance_loop(state.clone()));
    let app = build_router(state);
    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("cannot bind {listen}: {e}");
            return ExitCode::from(1);
        }
    };
    tracing::warn!(%listen, tls = tls.is_some(), version = env!("CARGO_PKG_VERSION"), "CipherDrop listening");
    serve::run(listener, app, limits, tls, shutdown_signal(), grace).await;
    // Ephemeral shares are intentionally dropped here; nothing is persisted.
    tracing::warn!("CipherDrop stopped; in-memory shares discarded");
    ExitCode::SUCCESS
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
}
