package net.rotko.zigner.domain.module

import android.content.Context
import io.parity.signer.uniffi.ModulePackageInfo
import io.parity.signer.uniffi.bakedModuleVersion
import io.parity.signer.uniffi.moduleSelfTest
import io.parity.signer.uniffi.moduleVerifyPackage
import org.json.JSONObject
import java.io.File

/**
 * A/B store for signed protocol-module packages (docs/update-architecture.md).
 *
 * Layout under filesDir/modules/:
 *   slot_a.zmod / slot_b.zmod - full signed packages (manifest || wasm)
 *   state.json - { active: "a"|"b"|null, staged, activeVersion, lastInstalled }
 *
 * Trust flow:
 *   stage()    - verify (2-of-3 sigs, hash, kernel gate, anti-rollback vs the
 *                persisted counter) -> write inactive slot
 *   activate() - re-verify + kernel self-test -> flip active, bump counter
 *   load()     - re-verify integrity of the active slot on every boot; ANY
 *                failure auto-reverts to the baked-in asset module. A bad or
 *                tampered slot can never brick signing.
 *
 * Delivery of the package bytes is out of scope here by design - adb, file,
 * or a future camera route all end at [stage].
 */
object ModuleSlotStore {
	private const val DIR = "modules"
	private const val STATE = "state.json"

	private fun dir(context: Context): File =
		File(context.filesDir, DIR).apply { mkdirs() }

	private fun slotFile(context: Context, slot: String): File =
		File(dir(context), "slot_$slot.zmod")

	private fun stateFile(context: Context): File = File(dir(context), STATE)

	/**
	 * The delta base: ALWAYS the module baked into the APK, never the active
	 * slot.
	 *
	 * Every device on a given APK holds this exact module, so one patch serves
	 * all of them and there is no chaining or version matrix. Using the active
	 * slot instead would also be a bug rather than merely a different choice:
	 * loadActiveVerified() re-verifies on every boot and cannot ask for the
	 * active module without recursing into itself, so it must use the baked
	 * copy - and a slot staged against a different base would fail that check
	 * and silently auto-revert.
	 */
	private fun deltaBase(context: Context): ByteArray =
		context.assets.open("modules/module0.wasm").use { it.readBytes() }

	private data class State(
		var active: String?,
		var staged: String?,
		var activeVersion: Long,
		var lastInstalled: Long,
	)

	private fun readState(context: Context): State {
		val baked = bakedModuleVersion().toLong()
		val f = stateFile(context)
		// Floor the rollback counter at the baked version, so shipping a
		// module in an APK also raises the bar for what a package may offer.
		if (!f.exists()) return State(null, null, 0, baked)
		return runCatching {
			val j = JSONObject(f.readText())
			State(
				j.optString("active").ifEmpty { null },
				j.optString("staged").ifEmpty { null },
				j.optLong("activeVersion", 0),
				maxOf(j.optLong("lastInstalled", 0), baked),
			)
		}.getOrElse { State(null, null, 0, baked) }
	}

	private fun writeState(context: Context, s: State) {
		val j = JSONObject()
			.put("active", s.active ?: "")
			.put("staged", s.staged ?: "")
			.put("activeVersion", s.activeVersion)
			.put("lastInstalled", s.lastInstalled)
		stateFile(context).writeText(j.toString())
	}

	/**
	 * Verify a delivered package and write it to the inactive slot.
	 * Throws (via uniffi) when any trust check fails - nothing is written
	 * in that case. Returns the manifest info for the confirm screen.
	 */
	fun stage(context: Context, packageBytes: ByteArray): ModulePackageInfo {
		val state = readState(context)
		// Deltas rebuild against the baked baseline; full packages ignore it.
		val info = moduleVerifyPackage(
			packageBytes.toUByteList(),
			state.lastInstalled.toUInt(),
			deltaBase(context).toUByteList(),
		)
		val target = if (state.active == "a") "b" else "a"
		slotFile(context, target).writeBytes(packageBytes)
		state.staged = target
		writeState(context, state)
		return info
	}

	/**
	 * Re-verify + self-test the staged slot, then make it active and bump
	 * the anti-rollback counter. Returns false (changing nothing) when any
	 * gate fails.
	 */
	fun activateStaged(context: Context): Boolean {
		val state = readState(context)
		val staged = state.staged ?: return false
		val pkg = runCatching { slotFile(context, staged).readBytes() }.getOrNull() ?: return false
		val info = runCatching {
			moduleVerifyPackage(
				pkg.toUByteList(),
				state.lastInstalled.toUInt(),
				deltaBase(context).toUByteList(),
			)
		}.getOrNull() ?: return false
		if (!moduleSelfTest(info.wasm)) return false
		state.active = staged
		state.staged = null
		state.activeVersion = info.moduleVersion.toLong()
		state.lastInstalled = info.moduleVersion.toLong()
		writeState(context, state)
		ProtocolModule.invalidate()
		return true
	}

	/**
	 * Load the active slot's verified wasm, or null to fall back to the
	 * baked-in asset. Verification failure of the active slot auto-reverts
	 * (clears active) so the next load doesn't retry a bad slot.
	 */
	/**
	 * Version of the module actually in force: the active slot when there is
	 * one, otherwise the module baked into the APK. This is what an update
	 * replaces, so it is what the confirm screen must show - the baked version
	 * alone would understate it whenever a slot is active.
	 */
	fun activeVersion(context: Context): Long {
		val state = readState(context)
		val baked = bakedModuleVersion().toLong()
		return if (state.active != null) maxOf(state.activeVersion, baked) else baked
	}

	fun loadActiveVerified(context: Context): ByteArray? {
		val state = readState(context)
		val active = state.active ?: return null
		// The APK wins when it is newer. filesDir survives APK updates, so a
		// device that ever applied a module update would otherwise keep
		// shadowing the baked module forever - an APK shipping a module fix
		// would be silently ignored on exactly the devices most likely to
		// need it. The baked copy arrives signed by the app signing key
		// through the OS, so it is the more authoritative of the two.
		if (state.activeVersion <= bakedModuleVersion().toLong()) {
			revertToAsset(context, state)
			return null
		}
		val pkg = runCatching { slotFile(context, active).readBytes() }.getOrNull()
		if (pkg == null) {
			revertToAsset(context, state)
			return null
		}
		// Integrity/authenticity re-check on every load. The rollback floor
		// is the active version minus one: the slot must still be exactly
		// the version we activated (or newer, which cannot happen).
		val floor = (state.activeVersion - 1).coerceAtLeast(0)
		val info = runCatching {
			moduleVerifyPackage(
				pkg.toUByteList(),
				floor.toUInt(),
				deltaBase(context).toUByteList(),
			)
		}.getOrNull()
		if (info == null || info.moduleVersion.toLong() != state.activeVersion) {
			revertToAsset(context, state)
			return null
		}
		return info.wasm.toByteArray()
	}

	private fun revertToAsset(context: Context, state: State) {
		state.active = null
		state.activeVersion = 0
		// lastInstalled is NOT lowered - anti-rollback survives reverts
		writeState(context, state)
		ProtocolModule.invalidate()
	}

	/** Current state summary for a settings/debug surface. */
	fun status(context: Context): String {
		val s = readState(context)
		return if (s.active != null) {
			"module v${s.activeVersion} (slot ${s.active})"
		} else {
			"module #0 (built-in)"
		}
	}
}
