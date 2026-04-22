package net.rotko.zigner.screens.scan.camera

import android.annotation.SuppressLint
import android.os.Trace
import androidx.camera.core.ImageProxy
import androidx.lifecycle.ViewModel
import com.google.mlkit.vision.barcode.BarcodeScanner
import com.google.mlkit.vision.common.InputImage
import net.rotko.zigner.domain.encodeHex
import net.rotko.zigner.domain.submitErrorState
import io.parity.signer.uniffi.BananaSplitRecoveryResult
import io.parity.signer.uniffi.DecodeSequenceResult
import io.parity.signer.uniffi.qrparserGetPacketsTotal
import io.parity.signer.uniffi.qrparserTryDecodeQrSequence
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject
import timber.log.Timber


class CameraViewModel() : ViewModel() {

	val isTorchEnabled = MutableStateFlow(false)

	private val _bananaSplitPayload = MutableStateFlow<List<String>?>(null)
	val bananaSplitPayload: StateFlow<List<String>?> =
		_bananaSplitPayload.asStateFlow()

	private val _pendingTransactionPayloads =
		MutableStateFlow<Set<String>>(emptySet())
	val pendingTransactionPayloads: StateFlow<Set<String>> =
		_pendingTransactionPayloads.asStateFlow()

	// Penumbra sign request payload (detected by 530310 prefix)
	private val _penumbraSignRequestPayload = MutableStateFlow<String?>(null)
	val penumbraSignRequestPayload: StateFlow<String?> =
		_penumbraSignRequestPayload.asStateFlow()

	// Cosmos sign request payload (detected by 530510 prefix)
	private val _cosmosSignRequestPayload = MutableStateFlow<String?>(null)
	val cosmosSignRequestPayload: StateFlow<String?> =
		_cosmosSignRequestPayload.asStateFlow()

	// Zcash simple sign request payload (detected by 530402 prefix)
	private val _zcashSimpleSignPayload = MutableStateFlow<String?>(null)
	val zcashSimpleSignPayload: StateFlow<String?> =
		_zcashSimpleSignPayload.asStateFlow()

	// UR backup frames (multipart UR QR codes starting with "ur:")
	private val _urBackupFrames = MutableStateFlow<List<String>>(emptyList())
	val urBackupFrames: StateFlow<List<String>> = _urBackupFrames.asStateFlow()
	private val _urBackupComplete = MutableStateFlow<List<String>?>(null)
	val urBackupComplete: StateFlow<List<String>?> = _urBackupComplete.asStateFlow()

	// UR zcash-notes frames (note sync via animated QR)
	private val _zcashNotesFrames = MutableStateFlow<List<String>>(emptyList())
	private val _zcashNotesComplete = MutableStateFlow<List<String>?>(null)
	val zcashNotesComplete: StateFlow<List<String>?> = _zcashNotesComplete.asStateFlow()

	// UR zcash-pczt frames (PCZT signing via animated QR)
	private val _zcashPcztFrames = MutableStateFlow<List<String>>(emptyList())
	private val _zcashPcztComplete = MutableStateFlow<List<String>?>(null)
	val zcashPcztComplete: StateFlow<List<String>?> = _zcashPcztComplete.asStateFlow()

	// JSON payloads (detected by {"frost":...} or {"auth":...} prefix)
	private val _frostPayload = MutableStateFlow<JSONObject?>(null)
	val frostPayload: StateFlow<JSONObject?> = _frostPayload.asStateFlow()
	private val _authPayload = MutableStateFlow<JSONObject?>(null)
	val authPayload: StateFlow<JSONObject?> = _authPayload.asStateFlow()
	private val _zidSignPayload = MutableStateFlow<JSONObject?>(null)
	val zidSignPayload: StateFlow<JSONObject?> = _zidSignPayload.asStateFlow()

	private val _dynamicDerivationPayload =
		MutableStateFlow<String?>(null)
	val dynamicDerivationPayload: StateFlow<String?> =
		_dynamicDerivationPayload.asStateFlow()

	private val _dynamicDerivationTransactionPayload =
		MutableStateFlow<List<String>?>(null)
	val dynamicDerivationTransactionPayload: StateFlow<List<String>?> =
		_dynamicDerivationTransactionPayload.asStateFlow()

	private val _total = MutableStateFlow<Int?>(null)
	private val _captured = MutableStateFlow<Int?>(null)

	// Observables for model data
	internal val total: StateFlow<Int?> = _total.asStateFlow()
	internal val captured: StateFlow<Int?> = _captured.asStateFlow()

	// payload of currently scanned qr codes for multiqr transaction like metadata update.
	private var currentMultiQrTransaction = mutableSetOf<String>()

	/**
	 * Barcode detecting function.
	 * This uses experimental features
	 */
	@SuppressLint("UnsafeOptInUsageError")
	fun processFrame(
		barcodeScanner: BarcodeScanner,
		imageProxy: ImageProxy
	) {
		Trace.beginSection("process frame")
		if (imageProxy.image == null) return
		val inputImage = InputImage.fromMediaImage(
			imageProxy.image!!,
			imageProxy.imageInfo.rotationDegrees,
		)

		barcodeScanner.process(inputImage)
			.addOnSuccessListener { barcodes ->
				Trace.beginSection("process frame vault code")
				barcodes.forEach {
					// Check for UR QR codes first (text-based, start with "ur:")
					val textValue = it?.rawValue
					if (textValue != null && textValue.lowercase().startsWith("ur:")) {
						processUrFrame(textValue)
						return@forEach
					}

					// Check for FROST JSON QR codes ({"frost":...})
					if (textValue != null && textValue.trimStart().startsWith("{")) {
						try {
							val json = JSONObject(textValue)
							if (json.has("frost")) {
								resetScanValues()
								_frostPayload.value = json
								return@forEach
							}
							if (json.has("auth")) {
								resetScanValues()
								_authPayload.value = json
								return@forEach
							}
							if (json.optString("type") == "zid-sign") {
								resetScanValues()
								_zidSignPayload.value = json
								return@forEach
							}
						} catch (_: Exception) { /* not valid JSON, continue */ }
					}

					// Try rawBytes first; fall back to rawValue for byte-mode QR codes
					// where ML Kit may return null rawBytes but valid Latin-1 text
					val fromRawBytes = it?.rawBytes?.encodeHex()
					val fromRawValue = it?.rawValue?.let { text ->
						text.map { ch -> "%02x".format(ch.code and 0xFF) }
							.joinToString("")
							.takeIf { hex -> hex.length >= 6 && hex.startsWith("53") }
					}
					val payloadString = fromRawBytes ?: fromRawValue

					if (!currentMultiQrTransaction.contains(payloadString) && !payloadString.isNullOrEmpty()) {
						val knownTotal = total.value

						if (knownTotal == null) {
							try {
								val proposeTotal =
									qrparserGetPacketsTotal(payloadString, true).toInt()
								if (proposeTotal == 1) {
									decode(listOf(payloadString))
								} else {
									currentMultiQrTransaction += payloadString
									_captured.value = currentMultiQrTransaction.size
									_total.value = proposeTotal
								}
							} catch (e: java.lang.Exception) {
								Timber.d(e, "getPacketsTotal failed")
							}
						} else {
							currentMultiQrTransaction += payloadString

							if (currentMultiQrTransaction.size >= knownTotal) {
								decode(currentMultiQrTransaction.toList())
							} else {
								_captured.value = currentMultiQrTransaction.size
							}
						}
					}
				}
				Trace.endSection()
			}
			.addOnFailureListener {
				Timber.e(it, "Scan failed")
			}
			.addOnCompleteListener {
				Trace.endSection()
				imageProxy.close()
			}
	}

	private fun decode(completePayload: List<String>) {
		try {
			val firstPayload = completePayload.firstOrNull() ?: return

			if (isPenumbraTransaction(firstPayload)) {
				resetScanValues()
				_penumbraSignRequestPayload.value = firstPayload
				return
			}

			if (isCosmosSignRequest(firstPayload)) {
				resetScanValues()
				_cosmosSignRequestPayload.value = firstPayload
				return
			}

			if (isZcashSimpleSignRequest(firstPayload)) {
				resetScanValues()
				_zcashSimpleSignPayload.value = firstPayload
				return
			}

			val payload = qrparserTryDecodeQrSequence(
				data = completePayload,
				password = null,
				cleaned = true,
			)
			when (payload) {
				is DecodeSequenceResult.BBananaSplitRecoveryResult -> {
					when (payload.b) {
						is BananaSplitRecoveryResult.RecoveredSeed -> {
							submitErrorState("cannot happen here that for scanning we don't have password request")
						}

						BananaSplitRecoveryResult.RequestPassword -> {
							resetScanValues()
							_bananaSplitPayload.value = completePayload
						}
					}
				}

				is DecodeSequenceResult.Other -> {
					resetScanValues()
					addPendingTransaction(payload.s)
				}

				is DecodeSequenceResult.DynamicDerivations -> {
					resetScanValues()
					_dynamicDerivationPayload.value = payload.s
				}

				is DecodeSequenceResult.DynamicDerivationTransaction -> {
					resetScanValues()
					_dynamicDerivationTransactionPayload.value = payload.s
				}
			}

		} catch (e: Exception) {
			Timber.e(e, "Single frame decode failed")
		}
	}

	/**
	 * Check if hex payload is a Penumbra transaction (prefix 530310)
	 */
	private fun isPenumbraTransaction(hexPayload: String): Boolean {
		return hexPayload.length >= 6 && hexPayload.substring(0, 6).equals("530310", ignoreCase = true)
	}

	/**
	 * Check if hex payload is a Cosmos sign request (prefix 530510)
	 */
	private fun isCosmosSignRequest(hexPayload: String): Boolean {
		return hexPayload.length >= 6 && hexPayload.substring(0, 6).equals("530510", ignoreCase = true)
	}

	/**
	 * Check if hex payload is a Zcash simple sign request (prefix 530402)
	 */
	private fun isZcashSimpleSignRequest(hexPayload: String): Boolean {
		return hexPayload.length >= 6 && hexPayload.substring(0, 6).equals("530402", ignoreCase = true)
	}

	fun resetZcashSimpleSign() {
		_zcashSimpleSignPayload.value = null
	}

	/**
	 * Process UR (Uniform Resource) QR frame for backup restore
	 * UR format: "ur:type/sequence/fragment" for multipart or "ur:type/fragment" for single
	 */
	private fun processUrFrame(urString: String) {
		val normalizedUr = urString.lowercase()

		when {
			normalizedUr.startsWith("ur:zigner-backup") -> {
				processUrFrameForType(urString, normalizedUr, "ur:zigner-backup", _urBackupFrames) { frames ->
					_urBackupComplete.value = frames
				}
			}
			normalizedUr.startsWith("ur:zcash-notes") -> {
				processUrFrameForType(urString, normalizedUr, "ur:zcash-notes", _zcashNotesFrames) { frames ->
					_zcashNotesComplete.value = frames
				}
			}
			normalizedUr.startsWith("ur:zcash-pczt") -> {
				processUrFrameForType(urString, normalizedUr, "ur:zcash-pczt", _zcashPcztFrames) { frames ->
					_zcashPcztComplete.value = frames
				}
			}
			else -> {
				Timber.d("Ignoring unknown UR type: $normalizedUr")
			}
		}
	}

	private fun processUrFrameForType(
		urString: String,
		normalizedUr: String,
		urPrefix: String,
		framesFlow: MutableStateFlow<List<String>>,
		onComplete: (List<String>) -> Unit,
	) {
		val currentFrames = framesFlow.value
		if (currentFrames.any { it.lowercase() == normalizedUr }) {
			return
		}

		val updatedFrames = currentFrames + urString
		framesFlow.value = updatedFrames

		val sequenceMatch = Regex("$urPrefix/(\\d+)-(\\d+)/").find(normalizedUr)
		if (sequenceMatch != null) {
			val (_, totalStr) = sequenceMatch.destructured
			val totalFrames = totalStr.toIntOrNull() ?: 1
			_total.value = totalFrames
			_captured.value = updatedFrames.size

			if (updatedFrames.size >= totalFrames) {
				resetScanValues()
				onComplete(updatedFrames)
			}
		} else {
			resetScanValues()
			onComplete(listOf(urString))
		}
	}

	private fun addPendingTransaction(payload: String) {
		_pendingTransactionPayloads.value += payload
	}

	/**
	 * Clears camera progress
	 */
	fun resetScanValues() {
		currentMultiQrTransaction = mutableSetOf()
		_captured.value = null
		_total.value = null
	}

	fun resetPendingTransactions() {
		_pendingTransactionPayloads.value = emptySet()
		_bananaSplitPayload.value = null
		_dynamicDerivationPayload.value = null
		_dynamicDerivationTransactionPayload.value = null
		_penumbraSignRequestPayload.value = null
		_cosmosSignRequestPayload.value = null
		_zcashSimpleSignPayload.value = null
		_urBackupFrames.value = emptyList()
		_urBackupComplete.value = null
		_zcashNotesFrames.value = emptyList()
		_zcashNotesComplete.value = null
		_zcashPcztFrames.value = emptyList()
		_zcashPcztComplete.value = null
		_frostPayload.value = null
		_authPayload.value = null
		_zidSignPayload.value = null
		resetScanValues()
	}

	fun resetUrBackup() {
		_urBackupFrames.value = emptyList()
		_urBackupComplete.value = null
	}

	fun resetZcashNotes() {
		_zcashNotesFrames.value = emptyList()
		_zcashNotesComplete.value = null
	}

	fun resetZcashPczt() {
		_zcashPcztFrames.value = emptyList()
		_zcashPcztComplete.value = null
	}

	fun resetFrostPayload() {
		_frostPayload.value = null
	}

	fun resetAuthPayload() {
		_authPayload.value = null
	}

	fun resetZidSignPayload() {
		_zidSignPayload.value = null
	}

	fun resetPenumbraSignRequest() {
		_penumbraSignRequestPayload.value = null
	}

	fun resetCosmosSignRequest() {
		_cosmosSignRequestPayload.value = null
	}
}
