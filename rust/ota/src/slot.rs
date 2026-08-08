//! Pure A/B firmware slot staging state machine (device-local, human-gated).
//!
//! Mirrors the pattern of `ModuleSlotStore.kt` but for firmware payloads and
//! kept pure (no filesystem) so it is fully unit-testable. The Android
//! adapter persists the bytes and calls these transitions.
//!
//! Flow: stage (verified) -> inactive slot [human tap] -> activate ->
//! successful-pending -> boot -> [new firmware confirms successful-boot] ->
//! durable -> emit result. Any failure discards the inactive slot; the
//! running (active) slot is never written during transfer.

use crate::stream::verify_payload_chunks;
use crate::Error;

/// Fail with a formatted crate error (internal helper).
macro_rules! err {
    ($($t:tt)*) => { return Err(Error(format!($($t)*))) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }
    pub fn byte(self) -> u8 {
        match self {
            Slot::A => b'A',
            Slot::B => b'B',
        }
    }
}

/// A staged (inactive) slot's verified contents + lifecycle state.
#[derive(Debug, Clone)]
pub struct StagedSlot {
    pub slot: Slot,
    pub fw_version: String,
    pub payload_sha256: [u8; 32],
    pub payload: Vec<u8>,
    /// Activated (human tap) and awaiting the new firmware's own
    /// `successful-boot` confirmation.
    pub boot_pending: bool,
    /// `successful-boot` durably confirmed; only then may a result be emitted.
    pub durable: bool,
    /// Device-signed result already emitted for this slot.
    pub result_emitted: bool,
}

/// Minimal verified-stream summary the store needs to stage a payload.
#[derive(Debug, Clone)]
pub struct StageRequest {
    pub fw_version: String,
    pub payload_sha256: [u8; 32],
    pub payload: Vec<u8>,
}

/// Pure A/B slot store state machine.
#[derive(Debug, Clone)]
pub struct FirmwareSlots {
    active: Slot,
    staged: Option<StagedSlot>,
    /// The slot that was active before the current activation (for revert).
    prior: Option<Slot>,
    /// True once the prior slot has become inert (after first verified boot).
    prior_inert: bool,
}

impl FirmwareSlots {
    pub fn new(active: Slot) -> Self {
        FirmwareSlots {
            active,
            staged: None,
            prior: None,
            prior_inert: false,
        }
    }

    pub fn active(&self) -> Slot {
        self.active
    }

    pub fn staged(&self) -> Option<&StagedSlot> {
        self.staged.as_ref()
    }

    /// Write the verified payload to the inactive slot after re-verifying the
    /// per-chunk hash. Any failure discards the inactive slot (returns Err,
    /// leaves `staged` None). The running slot is never touched.
    pub fn stage(&mut self, req: &StageRequest) -> Result<(), Error> {
        verify_payload_chunks(
            &req.payload,
            &req.payload_sha256,
            crate::stream::STAGING_CHUNK,
        )?;
        let target = self.active.other();
        self.staged = Some(StagedSlot {
            slot: target,
            fw_version: req.fw_version.clone(),
            payload_sha256: req.payload_sha256,
            payload: req.payload.clone(),
            boot_pending: false,
            durable: false,
            result_emitted: false,
        });
        Ok(())
    }

    /// Human tap: activate the staged (inactive) slot. It becomes
    /// boot-pending; it is NOT durable until its own firmware confirms
    /// `successful-boot`. Nothing happens if there is no staged slot.
    pub fn activate(&mut self) -> bool {
        let Some(staged) = self.staged.as_mut() else {
            return false;
        };
        self.prior = Some(self.active);
        self.prior_inert = false;
        self.active = staged.slot;
        staged.boot_pending = true;
        staged.durable = false;
        true
    }

    /// Called by the newly-booted firmware's verified-boot hook. Confirms
    /// `successful-boot`, marks the slot durable, and makes the prior slot
    /// inert. Returns true only if a boot-pending slot actually confirmed.
    pub fn confirm_successful_boot(&mut self) -> bool {
        if let Some(staged) = self.staged.as_mut() {
            if staged.boot_pending {
                staged.boot_pending = false;
                staged.durable = true;
                self.prior_inert = true;
                return true;
            }
        }
        false
    }

    /// Emit the device-signed result — ONLY after durable `successful-boot`.
    /// Returns the slot + fw_version to sign, or Err if not yet durable /
    /// already emitted.
    pub fn emit_result(&mut self, fw_version: &str) -> Result<(Slot, String), Error> {
        let Some(staged) = self.staged.as_mut() else {
            err!("no staged slot to emit a result for");
        };
        if !staged.durable {
            err!(
                "cannot emit result: slot {} has not durably confirmed successful-boot",
                sbyte(staged.slot)
            );
        }
        if staged.result_emitted {
            err!("result already emitted for slot {}", sbyte(staged.slot));
        }
        if staged.fw_version != fw_version {
            // The caller must sign with the version that actually booted.
            err!(
                "fw_version mismatch: staged {} but asked to emit {}",
                staged.fw_version,
                fw_version
            );
        }
        staged.result_emitted = true;
        Ok((staged.slot, staged.fw_version.clone()))
    }
}

fn sbyte(s: Slot) -> char {
    char::from(s.byte())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(version: &str, payload: &[u8]) -> (StageRequest, [u8; 32]) {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(payload);
        let sha: [u8; 32] = h.finalize().into();
        let r = StageRequest {
            fw_version: version.to_string(),
            payload_sha256: sha,
            payload: payload.to_vec(),
        };
        (r, sha)
    }

    #[test]
    fn stage_then_activate_then_boot_then_result() {
        let payload = b"firmware image bytes...".repeat(100);
        let (r, sha) = req("0.9.0", &payload);
        let mut store = FirmwareSlots::new(Slot::A);

        // Stage to inactive (B).
        store.stage(&r).unwrap();
        let staged = store.staged().unwrap();
        assert_eq!(staged.slot, Slot::B);
        assert_eq!(store.active(), Slot::A);
        assert!(!staged.boot_pending);
        assert!(!staged.durable);

        // Cannot emit before boot.
        assert!(store.emit_result("0.9.0").is_err());

        // Human tap -> activate.
        assert!(store.activate());
        assert_eq!(store.active(), Slot::B);
        let staged = store.staged().unwrap();
        assert!(staged.boot_pending);
        assert!(!staged.durable);

        // Still no result until successful boot.
        assert!(store.emit_result("0.9.0").is_err());

        // Verified-boot hook confirms.
        assert!(store.confirm_successful_boot());
        assert!(!store.confirm_successful_boot()); // already durable
        assert!(store.staged().unwrap().durable);

        // Now the result can be emitted (and only once).
        let (slot, ver) = store.emit_result("0.9.0").unwrap();
        assert_eq!(slot, Slot::B);
        assert_eq!(ver, "0.9.0");
        assert!(store.emit_result("0.9.0").is_err());

        assert_eq!(store.staged().unwrap().payload_sha256, sha);
    }

    #[test]
    fn failed_hash_discards_inactive_slot() {
        let payload = b"x".repeat(4096);
        let (mut r, _) = req("0.8.0", &payload);
        r.payload_sha256[0] ^= 0xff; // corrupt the hash
        let mut store = FirmwareSlots::new(Slot::A);
        assert!(store.stage(&r).is_err());
        assert!(store.staged().is_none());
        assert_eq!(store.active(), Slot::A);
    }

    #[test]
    fn activate_without_stage_is_a_noop() {
        let mut store = FirmwareSlots::new(Slot::A);
        assert!(!store.activate());
        assert_eq!(store.active(), Slot::A);
    }
}
