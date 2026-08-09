//! Kernel-side module runtime (docs/update-architecture.md).
//!
//! Loads a signed protocol module (wasm), links the `zigner_host` imports,
//! and drives the module ABI. Key custody, update verification,
//! anti-rollback and A/B slots layer on top of this; this file is the
//! execution seam only.

use wasmi::{Caller, Engine, Linker, Memory, Module, Store, TypedFunc};

pub struct ModuleRuntime {
    store: Store<()>,
    memory: Memory,
    alloc: TypedFunc<u32, u32>,
    summarize: TypedFunc<(u32, u32), u64>,
    sign: TypedFunc<(u32, u32, u32, u32, u32, u32), u64>,
    last_error: TypedFunc<(), u64>,
}

#[derive(Debug)]
pub enum HostError {
    Wasm(String),
    Module(String),
}

impl ModuleRuntime {
    pub fn load(wasm_bytes: &[u8]) -> Result<Self, HostError> {
        let engine = Engine::default();
        let module =
            Module::new(&engine, wasm_bytes).map_err(|e| HostError::Wasm(e.to_string()))?;
        let mut store = Store::new(&engine, ());

        let mut linker: Linker<()> = Linker::new(&engine);
        // Host entropy: the module's RedPallas signing is randomized and the
        // sandbox has no entropy of its own.
        linker
            .func_wrap(
                "zigner_host",
                "host_getrandom",
                |mut caller: Caller<'_, ()>, ptr: u32, len: u32| -> i32 {
                    let Some(wasmi::Extern::Memory(mem)) = caller.get_export("memory") else {
                        return 1;
                    };
                    let mut buf = vec![0u8; len as usize];
                    if rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng, &mut buf).is_err()
                    {
                        return 1;
                    }
                    if mem.write(&mut caller, ptr as usize, &buf).is_err() {
                        return 1;
                    }
                    0
                },
            )
            .map_err(|e| HostError::Wasm(e.to_string()))?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| HostError::Wasm(e.to_string()))?
            .start(&mut store)
            .map_err(|e| HostError::Wasm(e.to_string()))?;

        let memory = instance
            .get_memory(&store, "memory")
            .ok_or_else(|| HostError::Wasm("module exports no memory".into()))?;
        let get = |name: &str| {
            instance
                .get_func(&store, name)
                .ok_or_else(|| HostError::Wasm(format!("missing export {name}")))
        };
        let alloc = get("zigner_alloc")?
            .typed(&store)
            .map_err(|e| HostError::Wasm(e.to_string()))?;
        let summarize = get("zigner_summarize_request")?
            .typed(&store)
            .map_err(|e| HostError::Wasm(e.to_string()))?;
        let sign = get("zigner_sign_request")?
            .typed(&store)
            .map_err(|e| HostError::Wasm(e.to_string()))?;
        let last_error = get("zigner_last_error")?
            .typed(&store)
            .map_err(|e| HostError::Wasm(e.to_string()))?;

        Ok(Self {
            store,
            memory,
            alloc,
            summarize,
            sign,
            last_error,
        })
    }

    fn write_in(&mut self, bytes: &[u8]) -> Result<u32, HostError> {
        let ptr = self
            .alloc
            .call(&mut self.store, bytes.len() as u32)
            .map_err(|e| HostError::Wasm(e.to_string()))?;
        self.memory
            .write(&mut self.store, ptr as usize, bytes)
            .map_err(|e| HostError::Wasm(e.to_string()))?;
        Ok(ptr)
    }

    fn read_packed(&mut self, packed: u64) -> Result<Vec<u8>, HostError> {
        let ptr = (packed >> 32) as usize;
        let len = (packed & 0xffff_ffff) as usize;
        let mut buf = vec![0u8; len];
        self.memory
            .read(&self.store, ptr, &mut buf)
            .map_err(|e| HostError::Wasm(e.to_string()))?;
        Ok(buf)
    }

    fn module_error(&mut self) -> HostError {
        let packed = match self.last_error.call(&mut self.store, ()) {
            Ok(p) => p,
            Err(e) => return HostError::Wasm(e.to_string()),
        };
        match self.read_packed(packed) {
            Ok(b) => HostError::Module(String::from_utf8_lossy(&b).into_owned()),
            Err(e) => e,
        }
    }

    pub fn summarize_request(&mut self, payload: &[u8]) -> Result<Vec<u8>, HostError> {
        let ptr = self.write_in(payload)?;
        let packed = self
            .summarize
            .call(&mut self.store, (ptr, payload.len() as u32))
            .map_err(|e| HostError::Wasm(e.to_string()))?;
        if packed == 0 {
            return Err(self.module_error());
        }
        self.read_packed(packed)
    }

    pub fn sign_request(
        &mut self,
        payload: &[u8],
        seed_phrase: &str,
        account: u32,
        mainnet: bool,
    ) -> Result<Vec<u8>, HostError> {
        let p = self.write_in(payload)?;
        let s = self.write_in(seed_phrase.as_bytes())?;
        let packed = self
            .sign
            .call(
                &mut self.store,
                (
                    p,
                    payload.len() as u32,
                    s,
                    seed_phrase.len() as u32,
                    account,
                    u32::from(mainnet),
                ),
            )
            .map_err(|e| HostError::Wasm(e.to_string()))?;
        if packed == 0 {
            return Err(self.module_error());
        }
        self.read_packed(packed)
    }
}
pub mod manifest;

// ── kernel trust anchors (update architecture v1) ───────────────────────

/// Kernel (host API) version. Modules declare `min_kernel_version`; the
/// verifier refuses modules needing a newer kernel. Additive-only host API
/// changes bump this.
pub const KERNEL_VERSION: u32 = 1;

/// Version of the module baked into the APK as an asset.
///
/// The APK's copy is authoritative whenever it is newer than an installed
/// slot. filesDir survives APK updates, so without this a device that ever
/// applied a module update would keep shadowing the baked module forever -
/// an APK shipping a module security fix would be silently ignored. The slot
/// store compares against this and discards anything not newer.
///
/// Bump in lockstep with the asset. It is a constant rather than something
/// read from the asset because the baked module is a raw wasm with no
/// manifest, so it carries no version of its own.
pub const BAKED_MODULE_VERSION: u32 = 2;

/// The 2-of-3 release verifying keys, baked at build time per the update
/// architecture. PLACEHOLDER (all-zero) until the offline key ceremony -
/// `release_keys()` returns None for placeholders, so the kernel FAILS
/// CLOSED: no module package can verify until real pubkeys land here.
/// Rotation requires a kernel (store/USB) update by design.
pub const RELEASE_KEY_BYTES: [[u8; 32]; 3] = [[0u8; 32], [0u8; 32], [0u8; 32]];

/// Decode the baked release keys. None unless ALL THREE slots hold a real,
/// non-low-order key.
///
/// Note the hazard this guards: an all-zero slot is NOT rejected by ed25519
/// decoding. It decodes cleanly to a small-order point, and signatures under
/// a small-order key are forgeable. So "still a placeholder" has to be an
/// explicit check per slot, not something we can lean on the curve to catch.
pub fn release_keys() -> Option<[ed25519_dalek::VerifyingKey; 3]> {
    let mut keys = Vec::with_capacity(3);
    for kb in &RELEASE_KEY_BYTES {
        // Reject EACH placeholder slot, not just the all-three-zero case. An
        // all-zero encoding decodes to a *valid* ed25519 point - a small-order
        // one - so a partially-completed ceremony (real keys in some slots,
        // placeholder in the rest) would otherwise hand out a usable key whose
        // signatures are forgeable. Two placeholder slots left behind would let
        // an attacker forge 2-of-3 with no key compromise whatsoever.
        if kb.iter().all(|b| *b == 0) {
            return None;
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(kb).ok()?;
        // Belt and braces: refuse any low-order key, however it got in here.
        if key.is_weak() {
            return None;
        }
        keys.push(key);
    }
    keys.try_into().ok()
}

/// Kernel-side module self-test: instantiate the wasm and probe the ABI
/// with an unknown-tx-type envelope. A healthy module reports the named
/// module error; anything else (trap, instantiation failure, silence)
/// fails the test. Run before activating a staged slot - a bad module
/// can never brick signing.
pub fn self_test(wasm_bytes: &[u8]) -> bool {
    let Ok(mut rt) = ModuleRuntime::load(wasm_bytes) else {
        return false;
    };
    match rt.summarize_request(&[0x53, 0x04, 0x77, 0, 0, 0]) {
        Err(HostError::Module(msg)) => msg.contains("unknown zcash tx type"),
        _ => false,
    }
}

#[cfg(test)]
mod release_key_tests {
    use super::*;

    /// An all-zero slot decodes to a valid-but-small-order ed25519 key, so a
    /// partially-completed ceremony must be refused outright rather than
    /// yielding a key whose signatures can be forged.
    #[test]
    fn placeholder_slots_are_individually_refused() {
        let z = [0u8; 32];
        let decoded = ed25519_dalek::VerifyingKey::from_bytes(&z)
            .expect("all-zero decodes - that is precisely the hazard");
        assert!(
            decoded.is_weak(),
            "all-zero must be recognised as low-order"
        );
    }

    /// The shipped constant is still the placeholder, so the kernel must fail
    /// closed. This flips at the key ceremony.
    #[test]
    fn kernel_fails_closed_on_placeholder_keys() {
        assert!(
            release_keys().is_none(),
            "placeholder release keys must not yield a usable trust anchor"
        );
    }
}
