//! The manifest parser, which runs BEFORE any signature has been verified.
//!
//! Every byte here is attacker-controlled at the point this executes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((fields, consumed)) = module_host::manifest::parse_signing_prefix(data) {
        // A successful parse must report a length that is actually within the
        // input, or every downstream offset computed from it is wrong.
        assert!(consumed <= data.len());
        assert!(
            matches!(
                fields.payload_kind,
                module_host::manifest::PAYLOAD_FULL | module_host::manifest::PAYLOAD_BSDIFF_ZSTD
            ),
            "parser accepted an unknown payload kind"
        );
    }
});
