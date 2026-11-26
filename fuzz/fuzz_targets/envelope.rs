#![no_main]
use cipherdrop_protocol::api::CreateShareRequest;
use cipherdrop_protocol::payload::SecretPayload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = serde_json::from_slice::<CreateShareRequest>(data) {
        let _ = req.envelope().decode(1 << 20);
    }
    let _ = SecretPayload::from_bytes(data);
});
