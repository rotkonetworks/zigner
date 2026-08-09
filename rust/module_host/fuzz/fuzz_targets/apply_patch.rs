//! The most exposed parser in the update path.
//!
//! `apply_patch` consumes a payload that is NOT covered by the release
//! signatures - the manifest commits only to the RESULT hash - so a valid,
//! properly signed package can carry arbitrary bytes here and only be caught
//! at the final hash check. bsdiff and ruzstd are therefore handed hostile
//! input by design, and neither is our code.
//!
//! Any Ok or Err is acceptable. A panic, hang, or OOM is a finding.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split the input so the fuzzer controls the base as well as the patch:
    // bsdiff reads seek offsets against the base, and a base of a different
    // length is exactly the sort of mismatch a hostile package would present.
    let split = data.first().copied().unwrap_or(0) as usize;
    let rest = &data[data.len().min(1)..];
    let split = split.min(rest.len());
    let (base, patch) = rest.split_at(split);
    let _ = module_host::manifest::apply_patch(base, patch);
});
