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
