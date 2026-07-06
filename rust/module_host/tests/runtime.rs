//! Drives the REAL compiled protocol module under wasmi.
//! Prereq: cargo build -p pczt_signing --target wasm32-unknown-unknown --release

use module_host::{HostError, ModuleRuntime};

fn load() -> ModuleRuntime {
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../pczt_signing/target/wasm32-unknown-unknown/release/pczt_signing.wasm"
    ))
    .expect("build pczt_signing for wasm32 first");
    ModuleRuntime::load(&wasm).expect("instantiate module")
}

#[test]
fn module_rejects_unknown_tx_type_with_named_error() {
    let mut rt = load();
    let err = rt.summarize_request(&[0x53, 0x04, 0x77, 1, 2, 3]).unwrap_err();
    match err {
        HostError::Module(msg) => assert!(msg.contains("unknown zcash tx type"), "{msg}"),
        other => panic!("wrong error class: {other:?}"),
    }
}

#[test]
fn module_errors_cleanly_on_garbage_pczt() {
    let mut rt = load();
    // valid envelope, garbage body
    let mut payload = vec![0x53, 0x04, 0x03];
    payload.extend_from_slice(b"not a pczt");
    let err = rt.summarize_request(&payload).unwrap_err();
    assert!(matches!(err, HostError::Module(m) if m.contains("pczt parse")));
}

#[test]
fn sign_request_error_path_round_trips() {
    let mut rt = load();
    let mut payload = vec![0x53, 0x04, 0x03];
    payload.extend_from_slice(b"junk");
    let err = rt.sign_request(&payload, "abandon", 0, true).unwrap_err();
    assert!(matches!(err, HostError::Module(_)));
}
