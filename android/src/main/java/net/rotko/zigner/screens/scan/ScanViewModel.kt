package net.rotko.zigner.screens.scan

import net.rotko.zigner.screens.scan.transaction.frost.FrostRound2Binding
import android.content.Context
import timber.log.Timber
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import net.rotko.zigner.R
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.backend.UniffiInteractor
import net.rotko.zigner.domain.storage.RepoResult
import net.rotko.zigner.domain.storage.SeedRepository
import net.rotko.zigner.screens.scan.errors.LocalErrorSheetModel
import io.parity.signer.uniffi.PenumbraSignRequest
import io.parity.signer.uniffi.parsePenumbraSignRequest
import io.parity.signer.uniffi.signPenumbraTransaction as uniffiSignPenumbraTransaction
import io.parity.signer.uniffi.CosmosSignRequest
import io.parity.signer.uniffi.parseCosmosSignRequest
import io.parity.signer.uniffi.signCosmosTransaction as uniffiSignCosmosTransaction
import io.parity.signer.uniffi.ZcashNoteSyncResult
import io.parity.signer.uniffi.ModulePackageInfo
import io.parity.signer.uniffi.decodeAndVerifyZcashNotes
import io.parity.signer.uniffi.decodeUrZcashPczt
import io.parity.signer.uniffi.inspectZcashPczt
import io.parity.signer.uniffi.signZcashPcztUr
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.rotko.zigner.screens.scan.transaction.SignRequest
import net.rotko.zigner.screens.scan.transaction.SignatureResult


private const val TAG = "ScanViewModelTag"

/**
 * Shared ViewModel for all Scan flow components, not only camera related.
 */
class ScanViewModel : ViewModel() {

	private val uniffiInteractor: UniffiInteractor =
		ServiceLocator.uniffiInteractor
	private val seedRepository: SeedRepository by lazy { ServiceLocator.activityScope!!.seedRepository }

	/** Get first available seed phrase for auth signing */
	suspend fun getFirstSeedPhrase(): String {
		return when (val result = seedRepository.getAllSeeds()) {
			is RepoResult.Success -> result.result.values.firstOrNull() ?: ""
			is RepoResult.Failure -> ""
		}
	}

	/** Get first available seed name (NOT phrase) for display before signing.
	 *  Map iteration is unspecified on multi-seed devices; showing the chosen
	 *  name on-screen makes "which key is about to sign" visible to the user.
	 */
	suspend fun getFirstSeedName(): String {
		// Display-only: the seed NAME is not a secret (already shown without auth
		// on the key list, e.g. KeySetDetailsViewModel). Read it from the cached
		// non-auth source so the summarize/review step does NOT trigger a PIN /
		// biometric prompt - auth must fire exactly once, at Approve & Sign.
		// lastKnownSeedNames is populated at unlock (ResetUseCase.totalRefreshDbExist
		// -> getSeedNames) and stays sorted, matching the seed getFirstSeedPhrase
		// selects (getAllSeeds().values.firstOrNull() over the same sorted order).
		return seedRepository.getLastKnownSeedNames().firstOrNull() ?: ""
	}
	var bananaSplitPassword: MutableStateFlow<List<String>?> =
		MutableStateFlow(null)
	val transactionError: MutableStateFlow<LocalErrorSheetModel?> =
		MutableStateFlow(null)
	val errorWrongPassword = MutableStateFlow<Boolean>(false)

	// Penumbra signing state
	var penumbraSignRequest: MutableStateFlow<PenumbraSignRequest?> = MutableStateFlow(null)
	var penumbraSignatureQr: MutableStateFlow<ByteArray?> = MutableStateFlow(null)

	// Cosmos signing state
	var cosmosSignRequest: MutableStateFlow<CosmosSignRequest?> = MutableStateFlow(null)
	var cosmosSignatureQr: MutableStateFlow<ByteArray?> = MutableStateFlow(null)

	// UR backup restore state
	var urBackupFrames: MutableStateFlow<List<String>?> = MutableStateFlow(null)

	// Zcash note sync state
	var zcashNoteSyncResult: MutableStateFlow<ZcashNoteSyncResult?> = MutableStateFlow(null)
	var zcashNoteSyncFrames: MutableStateFlow<List<String>?> = MutableStateFlow(null)

	// PCZT signing state
	var zcashPcztUrParts: MutableStateFlow<List<String>?> = MutableStateFlow(null)

	// Protocol-module PCZT request state (prelude 530403/530404, hex payload)
	var modulePcztPayload: MutableStateFlow<String?> = MutableStateFlow(null)

	// Module package state (signed package bytes for installation)
	var modulePackageBytes: MutableStateFlow<ByteArray?> = MutableStateFlow(null)
	var modulePackageInfo: MutableStateFlow<ModulePackageInfo?> = MutableStateFlow(null)
	var modulePackageError: MutableStateFlow<String?> = MutableStateFlow(null)
	var releaseSignPrefix: MutableStateFlow<ByteArray?> = MutableStateFlow(null)

	// Unified signing state (replaces per-network state above)
	var signRequest: MutableStateFlow<SignRequest?> = MutableStateFlow(null)
	var signatureResult: MutableStateFlow<SignatureResult?> = MutableStateFlow(null)

	// FROST multisig state
	var frostPayload: MutableStateFlow<org.json.JSONObject?> = MutableStateFlow(null)
	// FROST DKG secrets held across rounds (memory only, cleared on completion/cancel)
	var frostDkgSecret: String = ""
	var frostDkgMaxSigners: UShort = 0u
	var frostDkgMinSigners: UShort = 0u
	var frostDkgLabel: String = ""
	var frostDkgMainnet: Boolean = true
	// FROST signing state held across rounds.
	// One nonce blob per Orchard action — round 1 generates them, round 2 consumes
	// per-action with that action's bundled commitments. Single-blob legacy field
	// kept for the older mnemonic-flow callers that sign one action at a time.
	var frostSignNonces: String = ""
	var frostSignNoncesPerAction: List<String> = emptyList()
	var frostSignKeyPackage: String = ""
	var frostSignEphemeralSeed: String = ""
	var frostSignWalletId: String = ""
	// What the user approved in round 1 (verified sighash + per-action alphas).
	// Round 2 signs only if its QR repeats exactly this - see FrostRound2Binding.
	var frostSignApproved: FrostRound2Binding.Approved? = null

	fun clearFrostDkgState() {
		frostDkgSecret = ""
	}

	fun clearFrostSignState() {
		frostSignNonces = ""
		frostSignNoncesPerAction = emptyList()
		frostSignKeyPackage = ""
		frostSignEphemeralSeed = ""
		frostSignApproved = null
	}

	// Auth challenge state
	var authPayload: MutableStateFlow<org.json.JSONObject?> = MutableStateFlow(null)
	// ZID sign request state
	var zidSignPayload: MutableStateFlow<org.json.JSONObject?> = MutableStateFlow(null)

	fun ifHasStateThenClear(): Boolean {
		return if (transactionError.value != null || errorWrongPassword.value || bananaSplitPassword.value != null || penumbraSignRequest.value != null || penumbraSignatureQr.value != null || cosmosSignRequest.value != null || cosmosSignatureQr.value != null || urBackupFrames.value != null || zcashNoteSyncResult.value != null || zcashNoteSyncFrames.value != null || modulePcztPayload.value != null || modulePackageBytes.value != null || releaseSignPrefix.value != null) {
			clearState()
			true
		} else {
			false
		}
	}

	fun clearState() {
		bananaSplitPassword.value = null
		transactionError.value = null
		errorWrongPassword.value = false
		penumbraSignRequest.value = null
		penumbraSignatureQr.value = null
		cosmosSignRequest.value = null
		cosmosSignatureQr.value = null
		urBackupFrames.value = null
		zcashNoteSyncResult.value = null
		zcashNoteSyncFrames.value = null
		zcashPcztUrParts.value = null
		modulePcztPayload.value = null
		modulePackageBytes.value = null
		modulePackageInfo.value = null
		modulePackageError.value = null
		releaseSignPrefix.value = null
		frostPayload.value = null
		clearFrostDkgState()
		clearFrostSignState()
		authPayload.value = null
		zidSignPayload.value = null
	}

	/**
	 * Verify zcash notes from UR frames and store in sled
	 */
	fun performZcashNoteSync(urFrames: List<String>, context: Context) {
		viewModelScope.launch {
			try {
				val result = decodeAndVerifyZcashNotes(urFrames)
				zcashNoteSyncResult.value = result
			} catch (e: Exception) {
				Timber.e(e, "Failed to verify zcash notes")
				transactionError.value = LocalErrorSheetModel(
					title = "Note sync failed",
					subtitle = e.message ?: "Failed to verify Zcash notes"
				)
				zcashNoteSyncFrames.value = null
			}
		}
	}

	fun clearZcashNoteSyncState() {
		zcashNoteSyncResult.value = null
		zcashNoteSyncFrames.value = null
	}

	/**
	 * Parse Penumbra sign request from QR hex and set it for display
	 */
	fun performPenumbraSignRequest(qrHex: String, context: Context) {
		try {
			val request = parsePenumbraSignRequest(qrHex)
			penumbraSignRequest.value = request
		} catch (e: Exception) {
			Timber.e(e, "Failed to parse Penumbra sign request")
			transactionError.value = LocalErrorSheetModel(
				title = context.getString(R.string.scan_screen_error_bad_format_title),
				subtitle = e.message ?: "Failed to parse Penumbra transaction"
			)
		}
	}

	/**
	 * Sign Penumbra transaction and generate signature QR bytes
	 */
	fun signPenumbraTransaction(context: Context) {
		val request = penumbraSignRequest.value ?: return

		viewModelScope.launch {
			try {
				when (val seeds = seedRepository.getAllSeeds()) {
					is RepoResult.Failure -> {
						Timber.e(TAG, "Failed to get seeds for Penumbra signing: ${seeds.error}")
						transactionError.value = LocalErrorSheetModel(
							title = "Signing error",
							subtitle = "Could not access seed phrases"
						)
					}
					is RepoResult.Success -> {
						val signatureBytes = signPenumbraMatchingSeed(seeds.result, request)
							?: return@launch
						penumbraSignatureQr.value = signatureBytes.map { it.toByte() }.toByteArray()
					}
				}
			} catch (e: Exception) {
				Timber.e(e, "Failed to sign Penumbra transaction")
				transactionError.value = LocalErrorSheetModel(
					title = "Signing failed",
					subtitle = e.message ?: "Unknown error during signing"
				)
			}
		}
	}

	/**
	 * Clear Penumbra signing state
	 */
	fun clearPenumbraState() {
		penumbraSignRequest.value = null
		penumbraSignatureQr.value = null
	}

	/**
	 * Parse Cosmos sign request from QR hex and set it for display
	 */
	fun performCosmosSignRequest(qrHex: String, context: Context) {
		try {
			val request = parseCosmosSignRequest(qrHex)
			cosmosSignRequest.value = request
		} catch (e: Exception) {
			Timber.e(e, "Failed to parse Cosmos sign request")
			transactionError.value = LocalErrorSheetModel(
				title = context.getString(R.string.scan_screen_error_bad_format_title),
				subtitle = e.message ?: "Failed to parse Cosmos transaction"
			)
		}
	}

	/**
	 * Sign Cosmos transaction and generate 64-byte signature
	 */
	fun signCosmosTransaction(context: Context) {
		val request = cosmosSignRequest.value ?: return

		viewModelScope.launch {
			try {
				when (val seeds = seedRepository.getAllSeeds()) {
					is RepoResult.Failure -> {
						Timber.e(TAG, "Failed to get seeds for Cosmos signing: ${seeds.error}")
						transactionError.value = LocalErrorSheetModel(
							title = "Signing error",
							subtitle = "Could not access seed phrases"
						)
					}
					is RepoResult.Success -> {
						val seedPhrase = seeds.result.values.firstOrNull()
						if (seedPhrase == null) {
							transactionError.value = LocalErrorSheetModel(
								title = "No seed found",
								subtitle = "No seed phrase available for signing"
							)
							return@launch
						}

						val signatureBytes = uniffiSignCosmosTransaction(seedPhrase, request)
						cosmosSignatureQr.value = signatureBytes.map { it.toByte() }.toByteArray()
					}
				}
			} catch (e: Exception) {
				Timber.e(e, "Failed to sign Cosmos transaction")
				transactionError.value = LocalErrorSheetModel(
					title = "Signing failed",
					subtitle = e.message ?: "Unknown error during signing"
				)
			}
		}
	}

	/**
	 * Clear Cosmos signing state
	 */
	fun clearCosmosState() {
		cosmosSignRequest.value = null
		cosmosSignatureQr.value = null
	}

	// ========================================================================
	// Unified signing methods
	// ========================================================================

	/**
	 * Parse any hex-based sign request (Penumbra or Cosmos)
	 * and set the unified signRequest state.
	 */
	fun performUnifiedSignRequest(qrHex: String, context: Context) {
		try {
			val prefix = if (qrHex.length >= 6) qrHex.substring(0, 6).lowercase() else ""
			val request: SignRequest = when {
				prefix == "530310" -> {
					SignRequest.Penumbra(parsePenumbraSignRequest(qrHex))
				}
				prefix == "530510" -> {
					SignRequest.Cosmos(parseCosmosSignRequest(qrHex))
				}
				else -> {
					throw IllegalArgumentException("Unknown QR prefix: $prefix")
				}
			}
			signRequest.value = request
		} catch (e: Exception) {
			Timber.e(e, "Failed to parse sign request")
			transactionError.value = LocalErrorSheetModel(
				title = context.getString(R.string.scan_screen_error_bad_format_title),
				subtitle = e.message ?: "Failed to parse transaction"
			)
		}
	}

	/**
	 * Parse Zcash PCZT from UR parts: decode → inspect → set signRequest.
	 */
	fun performZcashPcztRequest(urParts: List<String>, context: Context) {
		viewModelScope.launch {
			try {
				val pcztBytes = withContext(Dispatchers.Default) {
					decodeUrZcashPczt(urParts)
				}
				val inspection = withContext(Dispatchers.Default) {
					inspectZcashPczt(pcztBytes)
				}
				signRequest.value = SignRequest.ZcashPczt(
					urParts = urParts,
					inspection = inspection,
					pcztBytes = pcztBytes,
				)
			} catch (e: Exception) {
				Timber.e(e, "Failed to inspect PCZT")
				transactionError.value = LocalErrorSheetModel(
					title = "PCZT error",
					subtitle = e.message ?: "Failed to decode or inspect PCZT"
				)
			}
		}
	}

	/**
	 * Sign the current signRequest using the appropriate FFI function.
	 */
	fun signUnifiedTransaction(context: Context) {
		val req = signRequest.value ?: return

		viewModelScope.launch {
			try {
				when (req) {
					is SignRequest.Penumbra -> {
						val seeds = when (val loaded = seedRepository.getAllSeeds()) {
							is RepoResult.Failure -> {
								transactionError.value = LocalErrorSheetModel(
									title = "Signing Error",
									subtitle = "Could not access seed phrases"
								)
								return@launch
							}
							is RepoResult.Success -> loaded.result
						}
						val sigBytes = signPenumbraMatchingSeed(seeds, req.request)
							?: return@launch
						val hex = sigBytes.joinToString("") { "%02x".format(it.toByte()) }
						signatureResult.value = SignatureResult.HexQr(hex, req.networkName)
					}
					is SignRequest.Cosmos -> {
						val seedPhrase = getSeedPhrase() ?: return@launch
						val sigBytes = uniffiSignCosmosTransaction(seedPhrase, req.request)
						val hex = sigBytes.joinToString("") { "%02x".format(it.toByte()) }
						signatureResult.value = SignatureResult.HexQr(hex, req.networkName)
					}
					is SignRequest.ZcashPczt -> {
						val seedPhrase = getSeedPhrase() ?: return@launch
						val signedUrParts = withContext(Dispatchers.Default) {
							signZcashPcztUr(seedPhrase, 0u, req.urParts, 200u)
						}
						signatureResult.value = SignatureResult.UrParts(signedUrParts, req.networkName)
					}
				}
			} catch (e: Exception) {
				Timber.e(e, "Failed to sign transaction")
				transactionError.value = LocalErrorSheetModel(
					title = "Signing failed",
					subtitle = e.message ?: "Unknown error during signing"
				)
			}
		}
	}

	/**
	 * Clear unified signing state.
	 */
	fun clearSignState() {
		signRequest.value = null
		signatureResult.value = null
	}

	/**
	 * Sign with the first seed, in name order, that owns this request.
	 *
	 * Rust tries accounts 0..8 on the phrase it is given. A phrase that owns
	 * none of them returns "No key on this device owns this request." and the
	 * next seed is tried. Any other error stops the search.
	 */
	private fun signPenumbraMatchingSeed(
		seeds: Map<String, String>,
		request: PenumbraSignRequest,
	): List<UByte>? {
		if (seeds.isEmpty()) {
			transactionError.value = LocalErrorSheetModel(
				title = "No Seed Found",
				subtitle = "No seed phrase available for signing"
			)
			return null
		}
		var missed = false
		for (name in seeds.keys.sorted()) {
			val phrase = seeds[name]
			if (phrase.isNullOrEmpty()) continue
			try {
				return uniffiSignPenumbraTransaction(phrase, request)
			} catch (e: Exception) {
				val message = e.message.orEmpty()
				if (message.contains("No key on this device owns this request")) {
					missed = true
					continue
				}
				throw e
			}
		}
		transactionError.value = LocalErrorSheetModel(
			title = "Signing Failed",
			subtitle = if (missed) {
				"No key on this device owns this request."
			} else {
				"No seed phrase available for signing"
			}
		)
		return null
	}

	/**
	 * Get the first available seed phrase, or show error and return null.
	 */
	private suspend fun getSeedPhrase(): String? {
		return when (val seeds = seedRepository.getAllSeeds()) {
			is RepoResult.Failure -> {
				Timber.e(TAG, "Failed to get seeds: ${seeds.error}")
				transactionError.value = LocalErrorSheetModel(
					title = "Signing error",
					subtitle = "Could not access seed phrases"
				)
				null
			}
			is RepoResult.Success -> {
				val phrase = seeds.result.values.firstOrNull()
				if (phrase == null) {
					transactionError.value = LocalErrorSheetModel(
						title = "No seed found",
						subtitle = "No seed phrase available for signing"
					)
				}
				phrase
			}
		}
	}
}
