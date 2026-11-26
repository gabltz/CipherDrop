//! CipherDrop Rust SDK example.
//!
//! ```bash
//! CIPHERDROP_SERVER=https://paste.example.com cargo run -p cipherdrop-example
//! ```

use cipherdrop_sdk::{Client, CreateOptions};
use secrecy::ExposeSecret;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = std::env::var("CIPHERDROP_SERVER")?;
    let local = server.starts_with("http://127.0.0.1") || server.starts_with("http://localhost");
    let client = Client::builder(&server)
        .api_key(std::env::var("CIPHERDROP_API_KEY").ok())
        .allow_insecure_http(local)
        .build()?;

    // Encrypted locally; only ciphertext is uploaded.
    let share = client
        .create_secret(
            "rust synthetic secret",
            CreateOptions {
                ttl_seconds: Some(3600),
                max_reads: Some(1),
                title: Some("Rust example".into()),
                ..Default::default()
            },
        )
        .await?;
    println!("share link: {}", share.url.expose_secret());

    let payload = client.read(share.url.expose_secret(), None).await?;
    println!("decrypted: {}", payload.content);

    match client.read(share.url.expose_secret(), None).await {
        Err(e) => println!("second read: {}", e.api_code().unwrap_or("error")),
        Ok(_) => unreachable!("one-time share must not be readable twice"),
    }
    Ok(())
}
