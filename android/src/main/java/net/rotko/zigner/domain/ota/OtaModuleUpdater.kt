package net.rotko.zigner.domain.ota

import android.content.Context
import io.parity.signer.uniffi.OtaStreamManifestSummary
import io.parity.signer.uniffi.otaDecodeResult
import io.parity.signer.uniffi.otaDecodeStatus
import io.parity.signer.uniffi.otaEncodeResult
import io.parity.signer.uniffi.otaEncodeStatus
import io.parity.signer.uniffi.otaVerifyStream
import net.rotko.zigner.domain.module.ModuleSlotStore
import net.rotko.zigner.domain.module.toByteArray
import net.rotko.zigner.domain.module.toUByteList

/**
 * OTA delivery adapter (docs/design/zafu-ota-wire-freeze.md + rust/ota).
 *
 * The OTA wire delivers a small signed MODULE image (1-3 MB wasm) over a QR
 * `ur:zafu-stream` fountain. This adapter adds the OTA wire-contract gates on
 * TOP of the existing trusted module install path: it verifies the stream
 * against the pinned Zafu update key, and once verified routes the payload
 * onto the EXISTING single A/B store (ModuleSlotStore + ProtocolModule) for
 * the actual stage -> activate (human tap) -> verified-boot lifecycle.
 *
 * There is deliberately NO second/parallel firmware slot store: one coherent
 * update path. `ModuleSlotStore` performs its own module-host signature
 * re-verification + anti-rollback + auto-revert; the OTA layer is an outer
 * integrity/applicability gate, it never installs anything itself.
 *
 * Seed-isolation invariant preserved: the module never holds key material;
 * signing stays in the kernel (unchanged from ProtocolModule/module_host).
 *
 * The pinned update key and the manifest signature are supplied from secure
 * config / the carrier envelope; nothing is ever fetched over the network.
 */
object OtaModuleUpdater {

	/**
	 * Verify a scanned ur:zafu-stream fountain and, if applicable, stage the
	 * verified module payload into the existing A/B store.
	 *
	 * @return the parsed manifest summary for the confirm screen.
	 * @throws anything via uniffi when the stream is not authentic/applicable —
	 *         nothing is staged in that case.
	 */
	fun verifyAndStage(
		context: Context,
		urParts: List<String>,
		manifestSigHex: String,
		pinnedPubkeyHex: String,
		currentVersion: String,
		board: String,
		payload: ByteArray,
	): OtaStreamManifestSummary {
		val summary = otaVerifyStream(
			urParts,
			manifestSigHex,
			pinnedPubkeyHex,
			currentVersion,
			board,
		)
		// Route the verified module payload onto the single A/B store. The
		// store re-verifies the module package (own signatures + anti-rollback)
		// and writes only the INACTIVE slot; the running slot is never touched.
		ModuleSlotStore.stage(context, payload)
		return summary
	}

	/** Human tap: activate the staged update via the existing store. */
	fun activateStaged(context: Context): Boolean =
		ModuleSlotStore.activateStaged(context)

	/** Device-signed ur:zafu-result (single QR), shown to the wallet. */
	fun encodeResult(
		fwVersion: String,
		success: Boolean,
		slot: Byte,
		reqId: ByteArray,
		zidSecretKeyHex: String,
	): List<String> =
		otaEncodeResult(
			fwVersion,
			success,
			slot.toUByte(),
			reqId.toUByteList(),
			zidSecretKeyHex,
		)

	/** Device-signed ur:zafu-status (single QR), lost-result reconciliation. */
	fun encodeStatus(
		fwVersion: String,
		slot: Byte,
		successfulBoot: Boolean,
		zidSecretKeyHex: String,
	): List<String> =
		otaEncodeStatus(fwVersion, slot.toUByte(), successfulBoot, zidSecretKeyHex)

	/** Decode + verify a ur:zafu-result read back from a wallet scan. */
	fun decodeResult(urParts: List<String>) = otaDecodeResult(urParts)

	/** Decode + verify a ur:zafu-status read back from a wallet scan. */
	fun decodeStatus(urParts: List<String>) = otaDecodeStatus(urParts)
}
