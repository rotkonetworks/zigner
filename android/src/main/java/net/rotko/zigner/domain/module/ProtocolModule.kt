package net.rotko.zigner.domain.module

import android.content.Context
import io.parity.signer.uniffi.ModulePcztSummary
import io.parity.signer.uniffi.moduleSignRequest
import io.parity.signer.uniffi.moduleSummarizeRequest

/**
 * Protocol module access (docs/update-architecture.md).
 *
 * The active module comes from [ModuleSlotStore] (A/B slots, signed
 * packages, anti-rollback, self-test). When no slot is active - or the
 * active slot fails verification - the baked-in Module #0 asset is the
 * fallback, so signing always works.
 */
object ProtocolModule {
	private const val MODULE0_ASSET = "modules/module0.wasm"

	@Volatile
	private var cached: ByteArray? = null

	fun loadActive(context: Context): ByteArray =
		cached ?: (ModuleSlotStore.loadActiveVerified(context)
			?: context.assets.open(MODULE0_ASSET).use { it.readBytes() })
			.also { cached = it }

	/** Drop the cache after slot activation/revert. */
	fun invalidate() {
		cached = null
	}

	/** Confirmation data for a scanned PCZT payload (tx_type 0x03/0x04). */
	fun summarize(context: Context, payload: ByteArray): List<ModulePcztSummary> =
		moduleSummarizeRequest(loadActive(context).toUByteList(), payload.toUByteList())

	/** Sign after user confirmation; returns the response envelope for QR display. */
	fun sign(
		context: Context,
		payload: ByteArray,
		seedPhrase: String,
		account: UInt,
		mainnet: Boolean,
	): ByteArray =
		moduleSignRequest(
			loadActive(context).toUByteList(),
			payload.toUByteList(),
			seedPhrase,
			account,
			mainnet,
		).toByteArray()

	/**
	 * Zcash PCZT tx_types on the [0x53][crypto][tx_type] prelude:
	 * 0x03 single / 0x04 batch (full signed PCZT back), 0x05/0x06 the
	 * compact signatures-only variants (Ironwood QR shrink).
	 */
	fun isPcztPayload(payload: ByteArray): Boolean =
		payload.size > 3 &&
			payload[0] == 0x53.toByte() &&
			payload[1] == 0x04.toByte() &&
			(payload[2] == 0x03.toByte() ||
				payload[2] == 0x04.toByte() ||
				payload[2] == 0x05.toByte() ||
				payload[2] == 0x06.toByte())
}

internal fun ByteArray.toUByteList(): List<UByte> = map { it.toUByte() }
internal fun List<UByte>.toByteArray(): ByteArray =
	ByteArray(size) { i -> this[i].toByte() }
