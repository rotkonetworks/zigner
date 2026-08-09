//! `modpack` — release tooling for signed protocol-module packages.
//!
//! Deliberately three separate commands, because a release happens on three
//! separate machines and no one of them ever holds two release keys:
//!
//!   prepare    (build host)      module + changelog -> the bytes to be signed
//!   [scan]     (signing devices) each holder approves and returns 64 bytes
//!   assemble   (build host)      prefix + 2 signatures + payload -> .zmod
//!
//! `module_host::manifest::build_package` does all of that in one call and is
//! for tests only: it needs every key in one process, which is precisely what
//! 2-of-3 custody exists to prevent.

use std::process::ExitCode;

use module_host::manifest::{self, PAYLOAD_BSDIFF_ZSTD, PAYLOAD_FULL};
use sha2::{Digest, Sha256};

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// Group a digest into readable blocks. Matches the device's confirm screen so
/// the operator is comparing like with like - a bare 64-char run gets checked
/// two characters deep, which is the comparison an attacker wins.
fn fingerprint(hash: &[u8; 32]) -> String {
    hex::encode_upper(&hash[..8])
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Frames and wall-clock for an animated UR transfer, using the fountain
/// overhead the codebase already assumes (13/10) and the shipped playback
/// speeds. Printed because payload size is the whole reason deltas exist, and
/// a number in seconds is more use than a number in bytes.
fn transfer_estimate(bytes: usize) -> String {
    let frames = (bytes.div_ceil(600) * 13).div_ceil(10);
    let at = |ms: usize| {
        let s = frames * ms / 1000;
        format!("{}m{:02}s", s / 60, s % 60)
    };
    format!("{frames} frames  (fast {}, default {})", at(60), at(350))
}

struct Args(Vec<String>);

impl Args {
    fn opt(&self, name: &str) -> Option<String> {
        let i = self.0.iter().position(|a| a == name)?;
        self.0.get(i + 1).cloned()
    }
    fn req(&self, name: &str) -> Result<String, String> {
        self.opt(name).ok_or_else(|| format!("missing {name}"))
    }
    fn all(&self, name: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (i, a) in self.0.iter().enumerate() {
            if a == name {
                if let Some(v) = self.0.get(i + 1) {
                    out.push(v.clone());
                }
            }
        }
        out
    }
}

fn read(p: &str) -> Result<Vec<u8>, String> {
    std::fs::read(p).map_err(|e| format!("reading {p}: {e}"))
}

fn write(p: &str, b: &[u8]) -> Result<(), String> {
    std::fs::write(p, b).map_err(|e| format!("writing {p}: {e}"))
}

/// prepare: emit the signed region, and the payload it commits to.
fn prepare(a: &Args) -> Result<(), String> {
    let module = read(&a.req("--module")?)?;
    let version: u32 = a
        .req("--version")?
        .parse()
        .map_err(|_| "--version must be a number".to_string())?;
    let min_kernel: u32 = a
        .opt("--min-kernel")
        .unwrap_or_else(|| "1".into())
        .parse()
        .map_err(|_| "--min-kernel must be a number".to_string())?;
    let changelog = match a.opt("--changelog") {
        Some(p) => String::from_utf8_lossy(&read(&p)?).into_owned(),
        None => return Err("--changelog is required: it is inside the signed bytes and is what the user reads on the device".into()),
    };

    let module_hash = sha(&module);

    // A --base turns this into a delta release. Full modules are ~2 MB and
    // over half an hour of QR at the default speed; a delta is seconds.
    let (payload, kind, base_hash) = match a.opt("--base") {
        Some(base_path) => {
            let base = read(&base_path)?;
            let mut raw = Vec::new();
            bsdiff::diff(&base, &module, &mut raw).map_err(|e| format!("bsdiff: {e}"))?;
            let compressed =
                zstd::stream::encode_all(raw.as_slice(), 19).map_err(|e| format!("zstd: {e}"))?;
            (compressed, PAYLOAD_BSDIFF_ZSTD, sha(&base))
        }
        None => (module.clone(), PAYLOAD_FULL, [0u8; 32]),
    };

    let prefix = manifest::build_signing_prefix(
        module_hash,
        kind,
        base_hash,
        version,
        min_kernel,
        &changelog,
    );

    write(
        &a.opt("--out-prefix").unwrap_or_else(|| "prefix.bin".into()),
        &prefix,
    )?;
    write(
        &a.opt("--out-payload")
            .unwrap_or_else(|| "payload.bin".into()),
        &payload,
    )?;

    println!("module version : {version}");
    println!("module sha256  : {}", hex::encode(module_hash));
    println!(
        "fingerprint    : {}   <- must match what each device shows",
        fingerprint(&module_hash)
    );
    println!(
        "payload        : {} ({} bytes)",
        if kind == PAYLOAD_FULL {
            "full module"
        } else {
            "bsdiff+zstd delta"
        },
        payload.len()
    );
    if kind == PAYLOAD_BSDIFF_ZSTD {
        println!("  base sha256  : {}", hex::encode(base_hash));
        println!(
            "  vs full      : {:.0}x smaller",
            module.len() as f64 / payload.len() as f64
        );
    }
    println!("transfer       : {}", transfer_estimate(payload.len()));
    println!("\nNow have 2 of 3 holders scan prefix.bin and return their signatures.");
    Ok(())
}

/// assemble: join the prefix with device-made signatures and the payload.
fn assemble(a: &Args) -> Result<(), String> {
    let prefix = read(&a.req("--prefix")?)?;
    let payload = read(&a.req("--payload")?)?;

    let mut sigs: Vec<(u8, [u8; 64])> = Vec::new();
    for spec in a.all("--sig") {
        let (idx, hexsig) = spec
            .split_once(':')
            .ok_or_else(|| format!("--sig must be INDEX:HEX, got '{spec}'"))?;
        let idx: u8 = idx
            .parse()
            .map_err(|_| format!("bad key index in '{spec}'"))?;
        let raw = hex::decode(hexsig).map_err(|e| format!("bad signature hex: {e}"))?;
        let raw: [u8; 64] = raw
            .try_into()
            .map_err(|_| "a signature must be 64 bytes".to_string())?;
        if sigs.iter().any(|(i, _)| *i == idx) {
            return Err(format!("key index {idx} given twice - the device rejects duplicate indices, and two signatures from one key are not 2-of-3"));
        }
        sigs.push((idx, raw));
    }
    if sigs.len() < manifest::REQUIRED_SIGS {
        return Err(format!(
            "{} signature(s) given, {} required",
            sigs.len(),
            manifest::REQUIRED_SIGS
        ));
    }

    let pkg = manifest::assemble_package(&prefix, &sigs, &payload);
    let out = a.opt("--out").unwrap_or_else(|| "package.zmod".into());
    write(&out, &pkg)?;
    println!(
        "wrote {out} ({} bytes, {} signatures)",
        pkg.len(),
        sigs.len()
    );
    println!("\nVerify before shipping:  modpack verify --package {out} --key 0:HEX --key 1:HEX --key 2:HEX");
    Ok(())
}

/// verify: run the real device verifier over the finished package.
fn verify(a: &Args) -> Result<(), String> {
    let pkg = read(&a.req("--package")?)?;

    let mut keys = [[0u8; 32]; 3];
    let mut seen = [false; 3];
    for spec in a.all("--key") {
        let (idx, hexkey) = spec
            .split_once(':')
            .ok_or_else(|| format!("--key must be INDEX:HEX, got '{spec}'"))?;
        let idx: usize = idx
            .parse()
            .map_err(|_| format!("bad key index in '{spec}'"))?;
        if idx >= 3 {
            return Err(format!("key index {idx} out of range"));
        }
        let raw = hex::decode(hexkey).map_err(|e| format!("bad key hex: {e}"))?;
        keys[idx] = raw
            .try_into()
            .map_err(|_| "a public key must be 32 bytes".to_string())?;
        seen[idx] = true;
    }
    if !seen.iter().all(|s| *s) {
        return Err("all three release public keys are required - verification is against the full set the kernel bakes in, not just the signers".into());
    }

    let vks: Vec<ed25519_dalek::VerifyingKey> = keys
        .iter()
        .map(|k| {
            ed25519_dalek::VerifyingKey::from_bytes(k)
                .map_err(|e| format!("invalid public key: {e}"))
        })
        .collect::<Result<_, _>>()?;
    let vks: [ed25519_dalek::VerifyingKey; 3] = vks.try_into().unwrap();

    let base = match a.opt("--base") {
        Some(p) => Some(read(&p)?),
        None => None,
    };
    let last: u32 = a
        .opt("--last-installed")
        .unwrap_or_else(|| "0".into())
        .parse()
        .map_err(|_| "--last-installed must be a number".to_string())?;

    let v = manifest::verify_package_with_base(
        &pkg,
        &vks,
        module_host::KERNEL_VERSION,
        last,
        base.as_deref(),
    )
    .map_err(|e| format!("REJECTED: {e:?}"))?;

    println!("accepted");
    println!("  module version : {}", v.module_version);
    println!("  min kernel     : {}", v.min_kernel_version);
    println!("  module sha256  : {}", hex::encode(sha(&v.module_bytes)));
    println!("  fingerprint    : {}", fingerprint(&sha(&v.module_bytes)));
    println!("  changelog      : {}", v.description);
    Ok(())
}

const USAGE: &str = "\
modpack - zigner protocol-module release tooling

  prepare   --module M.wasm --version N --changelog NOTES.md
            [--base BAKED.wasm] [--min-kernel N]
            [--out-prefix prefix.bin] [--out-payload payload.bin]

            Emits the bytes the release keys sign. Pass --base to ship a
            delta instead of the whole module.

  assemble  --prefix prefix.bin --payload payload.bin
            --sig INDEX:HEX --sig INDEX:HEX [--out package.zmod]

            Joins signatures collected from offline devices.

  verify    --package package.zmod --key 0:HEX --key 1:HEX --key 2:HEX
            [--base BAKED.wasm] [--last-installed N]

            Runs the real device verifier. Do this before shipping.
";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first().cloned() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let args = Args(argv);
    let r = match cmd.as_str() {
        "prepare" => prepare(&args),
        "assemble" => assemble(&args),
        "verify" => verify(&args),
        _ => {
            eprint!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
