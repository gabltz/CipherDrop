//! Regenerates `testdata/vectors.json`.
//!
//! ```bash
//! cargo run -p cipherdrop-protocol --example generate_vectors > crates/protocol/testdata/vectors.json
//! ```
//!
//! All inputs are fixed synthetic values, so the output is deterministic.

use cipherdrop_protocol::aad::build_aad;
use cipherdrop_protocol::crypto::{ShareKey, derive_content_key, encrypt_deterministic};
use cipherdrop_protocol::encoding::b64_encode;
use cipherdrop_protocol::envelope::DecodedKdf;
use cipherdrop_protocol::payload::SecretPayload;
use serde_json::{Value, json};

fn seq<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add(i as u8))
}

struct Case {
    name: &'static str,
    description: &'static str,
    key: [u8; 32],
    nonce: [u8; 12],
    plaintext: Vec<u8>,
    password: Option<(&'static str, DecodedKdf)>,
}

fn kdf(salt_start: u8) -> DecodedKdf {
    DecodedKdf {
        salt: seq::<16>(salt_start),
        memory_kib: 19_456,
        iterations: 2,
        parallelism: 1,
    }
}

fn main() {
    let cases = vec![
        Case {
            name: "basic",
            description: "Minimal payload, no password, no padding.",
            key: seq::<32>(0x00),
            nonce: seq::<12>(0x00),
            plaintext: br#"{"content":"Hello, CipherDrop!"}"#.to_vec(),
            password: None,
        },
        Case {
            name: "title-syntax-unicode-padded",
            description: "Title, syntax hint, non-ASCII content; payload padded with spaces to 256 bytes.",
            key: seq::<32>(0x40),
            nonce: seq::<12>(0xa0),
            plaintext: SecretPayload {
                content: "fn main() {\n    println!(\"Grüße, 世界 🔐\");\n}\n".into(),
                title: Some("Synthetic snippet".into()),
                syntax: Some("rust".into()),
            }
            .to_bytes(256)
            .expect("serialize"),
            password: None,
        },
        Case {
            name: "empty-content",
            description: "Empty content string.",
            key: [0xff; 32],
            nonce: [0x00; 12],
            plaintext: br#"{"content":""}"#.to_vec(),
            password: None,
        },
        Case {
            name: "password",
            description: "Password-protected share using minimum Argon2id cost (19456 KiB, t=2, p=1).",
            key: seq::<32>(0x80),
            nonce: seq::<12>(0x10),
            plaintext: br#"{"content":"password protected synthetic secret","title":"PW test"}"#
                .to_vec(),
            password: Some(("correct horse battery staple", kdf(0x30))),
        },
        Case {
            name: "password-nfc",
            description: "Password containing U+00E9; must be NFC-normalized before Argon2id. Decrypting with the decomposed form \"cafe\\u0301-\\u00fcber\" must also succeed.",
            key: seq::<32>(0xc0),
            nonce: seq::<12>(0x20),
            plaintext: br#"{"content":"nfc"}"#.to_vec(),
            password: Some(("caf\u{e9}-\u{fc}ber", kdf(0x50))),
        },
    ];

    let mut vectors = Vec::new();
    let mut first_env: Option<(Value, [u8; 32])> = None;
    let mut pw_env: Option<(Value, [u8; 32])> = None;
    for c in &cases {
        let key = ShareKey::from_bytes(c.key);
        let env = encrypt_deterministic(&key, &c.plaintext, c.nonce, c.password).expect("encrypt");
        let cek =
            derive_content_key(&key, env.kdf.as_ref(), c.password.map(|(p, _)| p)).expect("cek");
        let wire = serde_json::to_value(env.to_wire()).expect("json");
        if first_env.is_none() {
            first_env = Some((wire.clone(), c.key));
        }
        if c.password.is_some() && pw_env.is_none() {
            pw_env = Some((wire.clone(), c.key));
        }
        vectors.push(json!({
            "name": c.name,
            "description": c.description,
            "key": b64_encode(&c.key),
            "fragment": format!("v1.{}", b64_encode(&c.key)),
            "password": c.password.map(|(p, _)| p),
            "aad": String::from_utf8(build_aad(env.kdf.as_ref())).expect("ascii"),
            "cek_hex": hex(cek.as_ref()),
            "plaintext": String::from_utf8(c.plaintext.clone()).expect("utf8"),
            "envelope": wire,
        }));
    }

    let (basic, basic_key) = first_env.expect("basic");
    let (pw, pw_key) = pw_env.expect("pw");
    let flip_last = |s: &str| {
        let mut chars: Vec<char> = s.chars().collect();
        let i = chars.len() - 2; // avoid the final char, whose low bits may be padding
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        chars.into_iter().collect::<String>()
    };
    let mut tampered_tag = basic.clone();
    tampered_tag["ciphertext"] = json!(flip_last(basic["ciphertext"].as_str().expect("s")));
    let mut tampered_nonce = basic.clone();
    tampered_nonce["nonce"] = json!(flip_last(basic["nonce"].as_str().expect("s")));
    let mut tampered_kdf = pw.clone();
    tampered_kdf["kdf"]["iterations"] = json!(3);
    let mut stripped_kdf = pw.clone();
    stripped_kdf.as_object_mut().expect("obj").remove("kdf");
    let mut bad_version = basic.clone();
    bad_version["version"] = json!(2);
    let mut padded_b64 = basic.clone();
    padded_b64["nonce"] = json!(format!("{}==", basic["nonce"].as_str().expect("s")));
    let mut short_nonce = basic.clone();
    short_nonce["nonce"] = json!(b64_encode(&[0u8; 8]));

    let invalid = json!([
        {"name": "modified-ciphertext", "key": b64_encode(&basic_key), "password": null, "envelope": tampered_tag, "expected_error": "decryption"},
        {"name": "modified-nonce", "key": b64_encode(&basic_key), "password": null, "envelope": tampered_nonce, "expected_error": "decryption"},
        {"name": "wrong-key", "key": b64_encode(&[0x11u8; 32]), "password": null, "envelope": basic, "expected_error": "decryption"},
        {"name": "wrong-password", "key": b64_encode(&pw_key), "password": "Correct horse battery staple", "envelope": pw, "expected_error": "decryption"},
        {"name": "modified-kdf-iterations", "key": b64_encode(&pw_key), "password": "correct horse battery staple", "envelope": tampered_kdf, "expected_error": "decryption"},
        {"name": "stripped-kdf", "key": b64_encode(&pw_key), "password": null, "envelope": stripped_kdf, "expected_error": "decryption"},
        {"name": "unsupported-version", "key": b64_encode(&basic_key), "password": null, "envelope": bad_version, "expected_error": "malformed"},
        {"name": "padded-base64", "key": b64_encode(&basic_key), "password": null, "envelope": padded_b64, "expected_error": "malformed"},
        {"name": "short-nonce", "key": b64_encode(&basic_key), "password": null, "envelope": short_nonce, "expected_error": "malformed"},
    ]);

    let doc = json!({
        "protocol_version": 1,
        "description": "CipherDrop protocol v1 deterministic test vectors. Synthetic data only. Valid vectors: implementations MUST decrypt `envelope` with `key` (+ `password`) to exactly `plaintext`, and MUST reproduce `envelope.ciphertext` when encrypting `plaintext` with the given key, nonce, password and KDF salt. Invalid vectors: implementations MUST reject them; `malformed` errors are raised while decoding the envelope, `decryption` errors by AES-GCM authentication.",
        "vectors": vectors,
        "invalid": invalid,
    });
    println!("{}", serde_json::to_string_pretty(&doc).expect("json"));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
