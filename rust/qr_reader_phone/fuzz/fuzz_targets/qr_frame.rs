//! The most reachable parser in the app.
//!
//! Every scanned frame goes through this before any chain dispatch and before
//! the scan-capability gate. The gate cannot cover it: which chain a payload
//! belongs to is not known until after the multipart header has been parsed.
//! So a user who has disabled every chain is still feeding this whatever a
//! camera can be pointed at.
//!
//! `src/parser.rs` is included directly rather than copied, so this fuzzes the
//! shipped code and cannot drift from it. The crate's real Error enum is
//! replaced by a shim below because it references transaction_parsing, which
//! anchors the whole Substrate dependency graph that cargo-fuzz cannot build.
#![no_main]

use libfuzzer_sys::fuzz_target;

/// Stand-in for `crate::Error`. parser.rs constructs exactly these three.
#[derive(Debug)]
pub enum Error {
    RaptorqFrame(String),
    LegacyFrame(String),
    UnexpectedData(String),
}
pub type Result<T> = std::result::Result<T, Error>;

#[path = "../../src/parser.rs"]
mod parser;

use std::convert::TryFrom;

fuzz_target!(|data: &[u8]| {
    // Frame decoding: raw bytes straight off a QR in byte mode.
    if let Ok(f) = parser::RaptorqFrame::try_from(data) {
        // A frame that parses must report a total the caller can act on.
        // total() feeding a loop bound or an allocation is exactly where a
        // wild value from a hostile header would land.
        let _ = f.total();
    }
    let _ = parser::LegacyFrame::try_from(data);

    // Envelope parsing: the same bytes as text, which is the other path the
    // Android layer takes when ML Kit hands back rawValue instead of rawBytes.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parser::parse_qr_payload(s);
    }
});
