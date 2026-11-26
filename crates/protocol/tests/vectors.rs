//! Verifies the committed cross-language test vectors.

use cipherdrop_protocol::aad::build_aad;
use cipherdrop_protocol::crypto::{ShareKey, decrypt, derive_content_key, encrypt_deterministic};
use cipherdrop_protocol::{EncryptedEnvelope, ProtocolError};
use serde_json::Value;

const VECTORS: &str = include_str!("../testdata/vectors.json");

fn load() -> Value {
    serde_json::from_str(VECTORS).expect("vectors.json must be valid JSON")
}

#[test]
fn valid_vectors_decrypt_and_reproduce() {
    let doc = load();
    let vectors = doc["vectors"].as_array().expect("vectors");
    assert!(vectors.len() >= 5);
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let key = ShareKey::from_b64(v["key"].as_str().unwrap()).unwrap();
        assert_eq!(
            v["fragment"].as_str().unwrap(),
            format!("v1.{}", v["key"].as_str().unwrap())
        );
        let pw = v["password"].as_str();
        let wire: EncryptedEnvelope = serde_json::from_value(v["envelope"].clone()).unwrap();
        let env = wire.decode(usize::MAX).unwrap();
        assert_eq!(
            String::from_utf8(build_aad(env.kdf.as_ref())).unwrap(),
            v["aad"].as_str().unwrap(),
            "{name}: aad"
        );
        let cek = derive_content_key(&key, env.kdf.as_ref(), pw).unwrap();
        assert_eq!(
            hex::encode(cek.as_ref()),
            v["cek_hex"].as_str().unwrap(),
            "{name}: cek"
        );
        let pt = decrypt(&key, &env, pw).unwrap();
        assert_eq!(
            pt.as_slice(),
            v["plaintext"].as_str().unwrap().as_bytes(),
            "{name}"
        );
        let again = encrypt_deterministic(
            &key,
            pt.as_slice(),
            env.nonce,
            pw.map(|p| (p, env.kdf.unwrap())),
        )
        .unwrap();
        assert_eq!(
            again.to_wire(),
            wire,
            "{name}: re-encryption must be byte-identical"
        );
    }
}

#[test]
fn nfc_vector_accepts_decomposed_password() {
    let doc = load();
    let v = doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "password-nfc")
        .unwrap();
    let key = ShareKey::from_b64(v["key"].as_str().unwrap()).unwrap();
    let wire: EncryptedEnvelope = serde_json::from_value(v["envelope"].clone()).unwrap();
    let env = wire.decode(usize::MAX).unwrap();
    assert!(decrypt(&key, &env, Some("cafe\u{301}-u\u{308}ber")).is_ok());
}

#[test]
fn invalid_vectors_rejected() {
    let doc = load();
    for v in doc["invalid"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let key = ShareKey::from_b64(v["key"].as_str().unwrap()).unwrap();
        let expected = v["expected_error"].as_str().unwrap();
        let decoded = serde_json::from_value::<EncryptedEnvelope>(v["envelope"].clone())
            .map_err(|_| ProtocolError::MalformedPayload)
            .and_then(|w| w.decode(usize::MAX));
        match (expected, decoded) {
            ("malformed", Err(_)) => {}
            ("malformed", Ok(_)) => panic!("{name}: expected malformed envelope"),
            ("decryption", Ok(env)) => {
                let r = decrypt(&key, &env, v["password"].as_str());
                assert!(
                    matches!(
                        r,
                        Err(ProtocolError::Decryption | ProtocolError::PasswordRequired)
                    ),
                    "{name}: {r:?}"
                );
            }
            (e, d) => panic!("{name}: unexpected {e} / {d:?}"),
        }
    }
}
