package net.rotko.zigner.domain.module

import android.content.Context
import io.parity.signer.uniffi.ModulePcztSummary
import io.parity.signer.uniffi.moduleSignRequest
import io.parity.signer.uniffi.moduleSummarizeRequest

/**
 * Protocol module access (docs/update-architecture.md).
 *
 * v1 wiring: Module #0 ships as an APK asset and is the only slot.
 * The A/B slot store + camera-update installer replace [loadActive]'s
 * body without touching call sites.
 */
object ProtocolModule {
	private const val MODULE0_ASSET = "modules/module0.wasm"

	@Volatile
	private var cached: ByteArray? = null

	fun loadActive(context: Context): ByteArray =
		cached ?: context.assets.open(MODULE0_ASSET).use { it.readBytes() }
			.also { cached = it }

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

	/** Zcash PCZT tx_types on the [0x53][crypto][tx_type] prelude. */
	fun isPcztPayload(payload: ByteArray): Boolean =
		payload.size > 3 &&
			payload[0] == 0x53.toByte() &&
			payload[1] == 0x04.toByte() &&
			(payload[2] == 0x03.toByte() || payload[2] == 0x04.toByte())
}

private fun ByteArray.toUByteList(): List<UByte> = map { it.toUByte() }
private fun List<UByte>.toByteArray(): ByteArray =
	ByteArray(size) { i -> this[i].toByte() }
