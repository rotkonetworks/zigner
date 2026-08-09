//! How long does it actually take to hand a protocol module across the airgap?
//!
//! The whole "never reinstall, just ship a module" story rests on the answer,
//! so measure it against the real asset and the real playback speeds rather
//! than estimating. Prints a table; asserts only the sanity bound.

const MODULE: &[u8] = include_bytes!("../../../android/src/main/assets/modules/module0.wasm");

#[test]
fn report_module_qr_transfer_time() {
    // Playback speeds the UI actually offers (QrPlaybackSpeed.kt).
    const SPEEDS: [(u32, &str); 3] = [(60, "fast"), (350, "default"), (700, "safe")];
    // Fountain overhead the codebase already assumes for PCZT: 13/10.
    const OVERHEAD_NUM: usize = 13;
    const OVERHEAD_DEN: usize = 10;

    println!("\nmodule0.wasm = {} bytes", MODULE.len());
    println!(
        "{:>10} {:>10} {:>12} {:>10} {:>10} {:>10}",
        "frag", "pure", "w/ 1.3x", "60ms", "350ms", "700ms"
    );

    for frag in [200usize, 300, 400, 600, 800] {
        let enc = ur::ur::Encoder::new(MODULE, frag, "zigner-module").expect("encoder");
        let pure = enc.fragment_count();
        let frames = (pure * OVERHEAD_NUM).div_ceil(OVERHEAD_DEN);
        let mut times = Vec::new();
        for (delay, _) in SPEEDS {
            let secs = frames as f64 * delay as f64 / 1000.0;
            times.push(format!("{:.0}m{:02.0}s", secs / 60.0, secs % 60.0));
        }
        println!(
            "{frag:>10} {pure:>10} {frames:>12} {:>10} {:>10} {:>10}",
            times[0], times[1], times[2]
        );
    }

    // Sanity: a QR frame carries ~2 chars per payload byte in bytewords, so
    // check one real frame to confirm the fragment size is QR-plausible.
    let mut enc = ur::ur::Encoder::new(MODULE, 400, "zigner-module").expect("encoder");
    let part = enc.next_part().expect("part");
    println!("\nframe at frag=400 is {} chars", part.len());
    assert!(!part.is_empty());
}
