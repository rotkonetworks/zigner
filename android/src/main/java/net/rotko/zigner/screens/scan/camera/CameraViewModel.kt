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

	// Zcash sign request payload (detected by 530402 prefix)
	private val _zcashSignRequestPayload = MutableStateFlow<String?>(null)
	val zcashSignRequestPayload: StateFlow<String?> =
		_zcashSignRequestPayload.asStateFlow()

	// Penumbra sign request payload (detected by 530310 prefix)
	private val _penumbraSignRequestPayload = MutableStateFlow<String?>(null)
	val penumbraSignRequestPayload: StateFlow<String?> =
		_penumbraSignRequestPayload.asStateFlow()

	// Cosmos sign request payload (detected by 530510 prefix)
	private val _cosmosSignRequestPayload = MutableStateFlow<String?>(null)
	val cosmosSignRequestPayload: StateFlow<String?> =
		_cosmosSignRequestPayload.asStateFlow()

	// UR backup frames (multipart UR QR codes starting with "ur:")
	private val _urBackupFrames = MutableStateFlow<List<String>>(emptyList())
	val urBackupFrames: StateFlow<List<String>> = _urBackupFrames.asStateFlow()
	private val _urBackupComplete = MutableStateFlow<List<String>?>(null)
	val urBackupComplete: StateFlow<List<String>?> = _urBackupComplete.asStateFlow()

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
			// Check for Zcash sign request first (prefix 530402)
			val firstPayload = completePayload.firstOrNull() ?: return
			if (isZcashSignRequest(firstPayload)) {
				resetScanValues()
				_zcashSignRequestPayload.value = firstPayload
				return
			}

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
	 * Check if hex payload is a Zcash sign request (prefix 530402)
	 */
	private fun isZcashSignRequest(hexPayload: String): Boolean {
		return hexPayload.length >= 6 && hexPayload.substring(0, 6).equals("530402", ignoreCase = true)
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
	 * Process UR (Uniform Resource) QR frame for backup restore
	 * UR format: "ur:type/sequence/fragment" for multipart or "ur:type/fragment" for single
	 */
	private fun processUrFrame(urString: String) {
		val normalizedUr = urString.lowercase()

		// Check if this is a zigner backup UR (ur:zigner-backup type)
		if (!normalizedUr.startsWith("ur:zigner-backup")) {
			Timber.d("Ignoring non-backup UR: $normalizedUr")
			return
		}

		// Check if this frame is already collected
		val currentFrames = _urBackupFrames.value
		if (currentFrames.any { it.lowercase() == normalizedUr }) {
			return
		}

		// Add frame to collection
		val updatedFrames = currentFrames + urString
		_urBackupFrames.value = updatedFrames

		// Parse sequence info from UR (format: ur:zigner-backup/1-3/... for multipart)
		val sequenceMatch = Regex("ur:zigner-backup/(\\d+)-(\\d+)/").find(normalizedUr)
		if (sequenceMatch != null) {
			val (_, totalStr) = sequenceMatch.destructured
			val totalFrames = totalStr.toIntOrNull() ?: 1
			_total.value = totalFrames
			_captured.value = updatedFrames.size

			// Check if we have all frames (fountain codes may need extra frames)
			if (updatedFrames.size >= totalFrames) {
				// Complete - signal backup restore ready
				resetScanValues()
				_urBackupComplete.value = updatedFrames
			}
		} else {
			// Single-part UR, complete immediately
			resetScanValues()
			_urBackupComplete.value = listOf(urString)
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
		_zcashSignRequestPayload.value = null
		_penumbraSignRequestPayload.value = null
		_cosmosSignRequestPayload.value = null
		_urBackupFrames.value = emptyList()
		_urBackupComplete.value = null
		resetScanValues()
	}

	fun resetUrBackup() {
		_urBackupFrames.value = emptyList()
		_urBackupComplete.value = null
	}

	fun resetZcashSignRequest() {
		_zcashSignRequestPayload.value = null
	}

	fun resetPenumbraSignRequest() {
		_penumbraSignRequestPayload.value = null
	}

	fun resetCosmosSignRequest() {
		_cosmosSignRequestPayload.value = null
	}
}
