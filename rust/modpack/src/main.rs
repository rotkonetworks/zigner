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
        payload.len() as u32,
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

    // Untagged signatures: the verifier matches each against the pinned keys, so
    // order does not matter and there is no index to pass. Reject a byte-identical
    // signature given twice (ed25519 is deterministic, so one key signing the same
    // prefix twice produces the same bytes) - that is one key, not two.
    let mut sigs: Vec<[u8; 64]> = Vec::new();
    for spec in a.all("--sig") {
        let raw = hex::decode(spec.trim()).map_err(|e| format!("bad signature hex: {e}"))?;
        let raw: [u8; 64] = raw
            .try_into()
            .map_err(|_| "a signature must be 64 bytes".to_string())?;
        if sigs.contains(&raw) {
            return Err(
                "the same signature was given twice - two signatures from one key are not 2-of-3"
                    .into(),
            );
        }
        sigs.push(raw);
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
    println!(
        "\nVerify before shipping:  modpack verify --package {out} --key HEX --key HEX --key HEX"
    );
    Ok(())
}

/// verify: run the real device verifier over the finished package.
fn verify(a: &Args) -> Result<(), String> {
    let pkg = read(&a.req("--package")?)?;

    // The full pinned set, order-independent (the verifier matches each signature
    // against all three). Pass three bare --key HEX; no index.
    let key_specs = a.all("--key");
    if key_specs.len() != 3 {
        return Err(format!(
            "exactly 3 release public keys required - verification is against the full set the kernel bakes in, not just the signers; got {}",
            key_specs.len()
        ));
    }
    let mut keys = [[0u8; 32]; 3];
    for (i, spec) in key_specs.iter().enumerate() {
        let raw = hex::decode(spec.trim()).map_err(|e| format!("bad key hex: {e}"))?;
        keys[i] = raw
            .try_into()
            .map_err(|_| "a public key must be 32 bytes".to_string())?;
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

/// sign: sign a manifest prefix with a raw ed25519 release key held as a FILE.
///
/// This is the software-key path, for the slot that is not a device - e.g. the
/// GitHub/CI key (slot 0), decrypted from its age file at release time. Device
/// holders instead sign on their zigner (`release_sign_request`), which derives
/// the key from the seed and never exports it. Both produce the SAME bytes: a
/// signature over `manifest::signing_message(prefix)` = DOMAIN || prefix, so a
/// file-key signature and a device signature are interchangeable in a package.
///
/// Output is one line `SIGHEX`, ready to paste into `modpack assemble --sig
/// SIGHEX`. The pubkey is printed to stderr so the operator can eyeball it
/// against the pinned set. Untagged: the verifier matches it against the keys.
fn sign(a: &Args) -> Result<(), String> {
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    let prefix = read(&a.req("--prefix")?)?;

    // Parse with the real parser before signing - never sign bytes we cannot
    // classify, and reject trailing bytes (display-one, sign-another). Mirrors
    // the device's `classify_request`.
    let (_, consumed) = manifest::parse_signing_prefix(&prefix)
        .map_err(|e| format!("not a module manifest: {e:?}"))?;
    if consumed != prefix.len() {
        return Err(format!(
            "trailing bytes after the manifest: signed region is {consumed}, got {}",
            prefix.len()
        ));
    }

    let raw = read(&a.req("--key")?)?;
    let key_bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
        format!(
            "--key must be a raw 32-byte ed25519 secret key (as `keygen` writes); got {} bytes",
            raw.len()
        )
    })?;
    let sk = SigningKey::from_bytes(&key_bytes);

    let msg = manifest::signing_message(&prefix);
    let sig = sk.sign(&msg);
    // The signature we emit must verify under our own key, or assemble/verify
    // will reject it later for no visible reason.
    sk.verifying_key()
        .verify(&msg, &sig)
        .map_err(|e| format!("self-verify failed (bad key?): {e}"))?;

    eprintln!(
        "signed with release pubkey {}",
        hex::encode(sk.verifying_key().to_bytes())
    );
    println!("{}", hex::encode(sig.to_bytes()));
    Ok(())
}

/// keygen: mint independent ed25519 release keypairs, OFFLINE.
///
/// `--count` defaults to 3 (a full all-software trust root). For the zigner
/// model - two device-held keys plus one GitHub/CI key - mint only the software
/// key with `--count 1`; the two device keys come from `release_signing_pubkey`
/// on each zigner and are never files.
///
/// This is the firmware trust root. The device pins all three verifying keys
/// (`module_host` `release_keys: [VerifyingKey; 3]`) and accepts a module only
/// if 2 of the 3 signed it - the same 2-of-3 the `prepare`/`assemble` split
/// enforces. Run this ONCE, on an air-gapped machine (see CEREMONY.md), then
/// never again for the life of the trust root.
///
/// Not FROST: three separate keys, three separate holders, any two of which can
/// authorise a release. That is deliberate - it is the same custody the rest of
/// this tool assumes (no process ever holds two keys).
///
/// Output: three raw 32-byte secret keys written 0600 (encrypt with `age` to
/// their holders and shred the raw, still offline), plus the three verifying
/// keys printed as hex and as a ready-to-paste `[VerifyingKey; 3]` snippet.
fn keygen(a: &Args) -> Result<(), String> {
    use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

    let out_dir = a.opt("--out-dir").unwrap_or_else(|| "release-keys".into());
    // Fail closed rather than clobber an existing trust root.
    if std::path::Path::new(&out_dir).exists() {
        return Err(format!(
            "{out_dir} already exists - refusing to overwrite a trust root. \
             Pick a fresh --out-dir or move the old one aside."
        ));
    }
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("mkdir {out_dir}: {e}"))?;

    // Slot names are advisory (the device only cares about position 0/1/2), but
    // labelling the files by intended holder makes the ceremony auditable.
    // Default all three; --count 1 mints only the software (GitHub/CI) key when
    // the other two slots are device-derived (release_signing_pubkey).
    let count: usize = match a.opt("--count") {
        None => 3,
        Some(s) => s
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=3).contains(n))
            .ok_or("--count must be 1, 2 or 3")?,
    };
    let holders = ["ci", "manager", "backup"];

    let mut sks: Vec<SigningKey> = Vec::with_capacity(count);
    let mut vks: Vec<VerifyingKey> = Vec::with_capacity(count);
    for _ in 0..count {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| format!("OS entropy: {e}"))?;
        let sk = SigningKey::from_bytes(&seed);
        seed.fill(0);
        vks.push(sk.verifying_key());
        sks.push(sk);
    }

    // Prove every generated key signs and verifies under the real verifier
    // BEFORE we trust it or the operator wipes anything. (Works for any count;
    // the 2-of-3 property is the pair of any two of these, exercised by the
    // sign/assemble/verify path, not something one key can demonstrate alone.)
    let msg = b"modpack-keygen-selftest-v1";
    for i in 0..count {
        let s = sks[i].sign(msg);
        vks[i]
            .verify(msg, &s)
            .map_err(|e| format!("selftest: slot {i} sign/verify failed: {e}"))?;
    }

    for (i, sk) in sks.iter().enumerate() {
        let path = format!("{out_dir}/slot{i}-{}.sk", holders[i]);
        write(&path, &sk.to_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod 0600 {path}: {e}"))?;
        }
    }

    println!("Self-test PASSED ({count} key(s) sign and verify).\n");
    println!("Wrote {count} raw secret key(s) (mode 0600) to {out_dir}/:");
    for i in 0..count {
        println!("  slot{i}-{}.sk", holders[i]);
    }
    println!("\nRelease VERIFYING keys - pin these (they are public, safe to copy):");
    for (i, vk) in vks.iter().enumerate() {
        println!(
            "  slot {i} ({}):  {}",
            holders[i],
            hex::encode(vk.to_bytes())
        );
    }
    if count == 3 {
        println!(
            "\nBake into RELEASE_KEY_BYTES (module_host) - or use the zafu.pro ceremony page:"
        );
        println!("  release_keys: [");
        for vk in &vks {
            println!(
                "    VerifyingKey::from_bytes(&hex!(\"{}\")).unwrap(),",
                hex::encode(vk.to_bytes())
            );
        }
        println!("  ],");
    } else {
        println!(
            "\nThis is {count} of the 3 slots. The remaining {} come from each zigner",
            3 - count
        );
        println!("(Release key screen -> slot:hex). Collect all 3 pubkeys in the zafu.pro");
        println!("ceremony page, which emits the RELEASE_KEY_BYTES constant with slots ordered.");
    }
    println!("\nStill OFFLINE, per holder: age -r <recipient> -o slotN-*.sk.age slotN-*.sk");
    println!("Then shred the raw:        shred -u {out_dir}/*.sk");
    if count == 1 {
        println!("Distribute: slot0 -> CI (commit the .age, age identity -> GitHub secret).");
    } else {
        println!(
            "Distribute: slot0 -> CI (age + GitHub secret), slot1 -> you, slot2 -> cold backup."
        );
    }
    Ok(())
}

const USAGE: &str = "\
modpack - zigner protocol-module release tooling

  keygen    [--out-dir release-keys] [--count 3]

            OFFLINE, ONCE. Mints independent ed25519 release keys the device
            pins (2-of-3). --count 1 mints only the software (GitHub/CI) key
            when the other two slots are zigner-derived. Prints the verifying
            keys to pin; writes secret keys 0600 to age-encrypt. See CEREMONY.md.

  sign      --key key.sk --prefix prefix.bin

            Sign a prefix with a FILE-held release key (the GitHub/CI key).
            Device holders sign on their zigner instead. Prints SIGHEX for
            `assemble`. Same signed bytes as the device, interchangeable.

  prepare   --module M.wasm --version N --changelog NOTES.md
            [--base BAKED.wasm] [--min-kernel N]
            [--out-prefix prefix.bin] [--out-payload payload.bin]

            Emits the bytes the release keys sign. Pass --base to ship a
            delta instead of the whole module.

  assemble  --prefix prefix.bin --payload payload.bin
            --sig HEX --sig HEX [--out package.zmod]

            Joins signatures collected from offline devices.

  verify    --package package.zmod --key HEX --key HEX --key HEX
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
        "keygen" => keygen(&args),
        "sign" => sign(&args),
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
