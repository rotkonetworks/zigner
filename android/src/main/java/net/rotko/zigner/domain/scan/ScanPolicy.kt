package net.rotko.zigner.domain.scan

import io.parity.signer.uniffi.ErrorDisplayed
import io.parity.signer.uniffi.scanReadable
import timber.log.Timber

/**
 * What the camera is allowed to hand to a parser.
 *
 * The camera is this app's only untrusted input. Everything an attacker
 * controls arrives through it, and the scan dispatcher routes purely on the
 * content of the payload - a six-character prefix decides which parser runs.
 * So a parser is reachable only when this device holds something it would
 * be used with: no Penumbra key, no Penumbra parsing; no Zcash key or FROST
 * wallet, no Zcash parsing. Polkadot and Cosmos are never reachable.
 *
 * The set comes from the Rust core (`db_handling::scan_policy`), derived
 * from the database each time the camera opens. There is no stored setting
 * that could drift from what the device actually holds.
 *
 * The gate is checked BEFORE a payload reaches a parser. Prefix matching to
 * classify the payload is a fixed-length string comparison and is not itself
 * the thing being defended against.
 */
enum class ScanCapability(val id: String, val label: String) {
	/** Signed protocol-module packages and release-signing prefixes. */
	MODULE("module", "Module updates"),

	/** Seed recovery (banana split) and backup import. */
	BACKUP("backup", "Recovery"),

	/** FROST key generation, which starts before any FROST wallet exists. */
	FROST_DKG("frost-dkg", "FROST wallet creation"),

	/** FROST signing rounds. */
	FROST("frost", "FROST signing"),

	/** Zcash: notes, PCZT, simple sign. */
	ZCASH("zcash", "Zcash"),

	PENUMBRA("penumbra", "Penumbra"),

	/** ZID challenge-response identity, derived from a seed. */
	AUTH("auth", "Identity"),

	/** Never readable: no screen left to route them to. */
	SUBSTRATE("substrate", "Polkadot / Substrate"),

	COSMOS("cosmos", "Cosmos"),
	;

	companion object {
		fun fromId(id: String): ScanCapability? = entries.firstOrNull { it.id == id }
	}
}

object ScanPolicy {
	/**
	 * Open on an empty device, because they are how a device stops being
	 * empty. Also what the camera falls back to if the lookup fails.
	 */
	val ALWAYS = setOf(
		ScanCapability.MODULE,
		ScanCapability.BACKUP,
		ScanCapability.FROST_DKG,
	)

	fun readable(): Set<ScanCapability> = try {
		scanReadable().mapNotNull { ScanCapability.fromId(it) }.toSet()
	} catch (e: ErrorDisplayed) {
		Timber.e("[SCAN] policy lookup failed, reading only recovery and updates: $e")
		ALWAYS
	}
}
