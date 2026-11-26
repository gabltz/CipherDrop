#![no_main]
use cipherdrop_protocol::url::{RevocationLink, ShareId, ShareLink};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ShareLink::parse(s);
        let _ = RevocationLink::parse(s);
        let _ = ShareId::parse(s);
    }
});
