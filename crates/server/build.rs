//! Locates the compiled frontend to embed.
//!
//! Uses `CIPHERDROP_DIST` if set, otherwise `<repo>/frontend/dist`. When no
//! build is present (e.g. `cargo test` before `npm run build`), a minimal
//! placeholder page is generated in `OUT_DIR` so the server still compiles;
//! that page states clearly that the web interface was not built.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=CIPHERDROP_DIST");
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let default = manifest.join("../../frontend/dist");
    let dist = std::env::var("CIPHERDROP_DIST")
        .map(PathBuf::from)
        .unwrap_or(default);
    println!("cargo:rerun-if-changed={}", dist.display());
    let index = dist.join("index.html");
    println!("cargo:rerun-if-changed={}", index.display());

    let chosen = if index.is_file() {
        dist.canonicalize().expect("canonicalize dist")
    } else {
        let out =
            PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("placeholder-dist");
        std::fs::create_dir_all(out.join("assets")).expect("create placeholder");
        std::fs::create_dir_all(out.join("swagger")).expect("create placeholder");
        let page = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noindex\"><title>CipherDrop</title></head><body><h1>CipherDrop</h1><p>The web interface was not built into this binary. Run <code>npm ci &amp;&amp; npm run build</code> in <code>frontend/</code> and rebuild. The API under <code>/api/v1</code> is fully functional.</p></body></html>";
        std::fs::write(out.join("index.html"), page).expect("write placeholder");
        std::fs::write(out.join("swagger/index.html"), page).expect("write placeholder");
        std::fs::write(
            out.join("favicon.svg"),
            "<svg xmlns=\"http://www.w3.org/2000/svg\"/>",
        )
        .expect("write");
        println!("cargo:warning=frontend/dist not found; embedding a placeholder page");
        out
    };
    println!("cargo:rustc-env=CIPHERDROP_DIST={}", chosen.display());
}
