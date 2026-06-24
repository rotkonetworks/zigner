package net.rotko.zigner.screens.scan

import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import net.rotko.zigner.R
import net.rotko.zigner.bottomsheets.password.EnterPassword
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.FakeNavigator
import net.rotko.zigner.screens.scan.addnetwork.AddedNetworkSheetsSubgraph
import net.rotko.zigner.screens.scan.backuprestore.BackupRestoreSubgraph
import net.rotko.zigner.screens.scan.bananasplitrestore.BananaSplitSubgraph
import net.rotko.zigner.screens.scan.camera.ScanScreen
import net.rotko.zigner.screens.scan.elements.WrongPasswordBottomSheet
import net.rotko.zigner.screens.scan.errors.LocalErrorBottomSheet
import net.rotko.zigner.screens.scan.errors.LocalErrorSheetModel
import net.rotko.zigner.screens.scan.transaction.TransactionPreviewType
import net.rotko.zigner.screens.scan.transaction.TransactionsScreenFull
import net.rotko.zigner.screens.scan.transaction.AuthChallengeScreen
import net.rotko.zigner.screens.scan.transaction.ZidSignScreen
import net.rotko.zigner.screens.scan.transaction.frost.FrostDkgScreen
import net.rotko.zigner.screens.scan.transaction.frost.FrostSignScreen
import net.rotko.zigner.screens.scan.transaction.ZcashNoteSyncScreen
import net.rotko.zigner.screens.scan.transaction.ZcashPcztScreen
import net.rotko.zigner.screens.scan.transaction.UnifiedTransactionScreen
import net.rotko.zigner.screens.scan.transaction.UnifiedSignatureQrScreen
import net.rotko.zigner.screens.scan.transaction.dynamicderivations.AddDynamicDerivationScreenFull
import net.rotko.zigner.screens.scan.transaction.previewType
import net.rotko.zigner.ui.BottomSheetWrapperRoot
import io.parity.signer.uniffi.Action
import kotlinx.coroutines.launch

/**
 * Navigation Subgraph with compose nav controller for those Key Set screens which are not part of general
 * Rust-controlled navigation
 */
@Composable
fun ScanNavSubgraph(
	onCloseCamera: Callback,
	seedNameSuggestion: String?,
	openKeySet:(seedName: String) -> Unit,
) {
	val scanViewModel: ScanViewModel = viewModel()

	val transactions = scanViewModel.transactions.collectAsStateWithLifecycle()
	val signature = scanViewModel.signature.collectAsStateWithLifecycle()
	val bananaSplitPassword =
		scanViewModel.bananaSplitPassword.collectAsStateWithLifecycle()
	val dynamicDerivations =
		scanViewModel.dynamicDerivations.collectAsStateWithLifecycle()

	val transactionError =
		scanViewModel.transactionError.collectAsStateWithLifecycle()
	val passwordModel = scanViewModel.passwordModel.collectAsStateWithLifecycle()
	val errorWrongPassword =
		scanViewModel.errorWrongPassword.collectAsStateWithLifecycle()

	// Unified signing state
	val unifiedSignRequest = scanViewModel.signRequest.collectAsStateWithLifecycle()
	val unifiedSignatureResult = scanViewModel.signatureResult.collectAsStateWithLifecycle()

	// UR backup restore state
	val urBackupFrames = scanViewModel.urBackupFrames.collectAsStateWithLifecycle()

	// Zcash note sync state
	val zcashNoteSyncResult = scanViewModel.zcashNoteSyncResult.collectAsStateWithLifecycle()

	val addedNetworkName: MutableState<String?> =
		remember { mutableStateOf(null) }

	val showingModals = transactionError.value != null ||
		passwordModel.value != null || errorWrongPassword.value

	val backAction = {
		val wasState = scanViewModel.ifHasStateThenClear()
		if (!wasState) onCloseCamera()
	}
	BackHandler(onBack = backAction)

	val context = LocalContext.current

	//Full screens
	val transactionsValue = transactions.value
	val bananaQrData = bananaSplitPassword.value
	val dynamicDerivationsData = dynamicDerivations.value
	val urBackupData = urBackupFrames.value

	val zcashPcztParts = scanViewModel.zcashPcztUrParts.collectAsStateWithLifecycle()
	val frostData = scanViewModel.frostPayload.collectAsStateWithLifecycle()

	if (zcashPcztParts.value != null) {
		ZcashPcztScreen(
			urParts = zcashPcztParts.value!!,
			getSeedPhrase = { scanViewModel.getFirstSeedPhrase() },
			getSeedName = { scanViewModel.getFirstSeedName() },
			modifier = Modifier.statusBarsPadding(),
			onDone = { scanViewModel.zcashPcztUrParts.value = null },
		)
	} else if (frostData.value != null) {
		val json = frostData.value!!
		val frostType = json.optString("frost", "")
		timber.log.Timber.d("[FROST] routing frostType='$frostType' keys=${json.keys().asSequence().toList()}")
		val dismissFrost = { scanViewModel.frostPayload.value = null }
		val scanNextFrost = {
			// Dismiss screen, back to camera for next round QR
			scanViewModel.frostPayload.value = null
		}
		when (frostType) {
			"dkg1" -> {
				scanViewModel.frostDkgMaxSigners = json.optInt("n", 3).toUShort()
				scanViewModel.frostDkgMinSigners = json.optInt("t", 2).toUShort()
				scanViewModel.frostDkgLabel = json.optString("label", "")
				scanViewModel.frostDkgMainnet = json.optBoolean("mainnet", true)
				FrostDkgScreen(
					round = 1,
					maxSigners = scanViewModel.frostDkgMaxSigners,
					minSigners = scanViewModel.frostDkgMinSigners,
					label = scanViewModel.frostDkgLabel,
					mainnet = scanViewModel.frostDkgMainnet,
					onSecretUpdated = { scanViewModel.frostDkgSecret = it },
					onScanNext = scanNextFrost,
					modifier = Modifier.statusBarsPadding(),
					onDone = { dismissFrost(); scanViewModel.clearFrostDkgState() },
				)
			}
			"dkg2" -> {
				FrostDkgScreen(
					round = 2,
					maxSigners = scanViewModel.frostDkgMaxSigners,
					minSigners = scanViewModel.frostDkgMinSigners,
					label = scanViewModel.frostDkgLabel,
					mainnet = scanViewModel.frostDkgMainnet,
					previousSecret = scanViewModel.frostDkgSecret,
					broadcastsJson = json.optJSONArray("broadcasts")?.toString() ?: "[]",
					onSecretUpdated = { scanViewModel.frostDkgSecret = it },
					onScanNext = scanNextFrost,
					modifier = Modifier.statusBarsPadding(),
					onDone = { dismissFrost(); scanViewModel.clearFrostDkgState() },
				)
			}
			"dkg3" -> {
				// dkg3 trigger now carries `sk` (host-broadcast random) and `relay_url`
				// so zigner derives UFVK/address itself in part-3 and bakes them into
				// the r3 ack — eliminates the post-DKG metadata round-trip.
				FrostDkgScreen(
					round = 3,
					maxSigners = scanViewModel.frostDkgMaxSigners,
					minSigners = scanViewModel.frostDkgMinSigners,
					label = scanViewModel.frostDkgLabel,
					mainnet = json.optBoolean("mainnet", scanViewModel.frostDkgMainnet),
					previousSecret = scanViewModel.frostDkgSecret,
					// keys mirror the relay-tag convention (R1:/R2:) used by
					// the mnemonic flow on the WSS relay.
					round1BroadcastsJson = json.optJSONArray("r1")?.toString() ?: "[]",
					round2PackagesJson = json.optJSONArray("r2")?.toString() ?: "[]",
					skHex = json.optString("sk", ""),
					relayUrl = json.optString("relay_url", ""),
					onSecretUpdated = { scanViewModel.frostDkgSecret = it },
					onScanNext = scanNextFrost,
					modifier = Modifier.statusBarsPadding(),
					onDone = { dismissFrost(); scanViewModel.clearFrostDkgState() },
				)
			}
			"sign1" -> {
				val pkg = json.optString("publicKeyPackage", "")
				val summaryJson = json.optJSONObject("summary")
				val summaryText = summaryJson?.let {
					val rec = it.optString("recipient", "")
					val amount = it.optString("amountZat", "0").toLongOrNull() ?: 0L
					val fee = it.optString("feeZat", "0").toLongOrNull() ?: 0L
					val zec = String.format("%.8f", amount / 1e8).trimEnd('0').trimEnd('.')
					val feeZec = String.format("%.8f", fee / 1e8).trimEnd('0').trimEnd('.')
					val t = it.optInt("threshold", 0)
					val n = it.optInt("maxSigners", 0)
					"$t-of-$n · send $zec ZEC · fee $feeZec ZEC\n→ ${rec.take(16)}…${rec.takeLast(8)}"
				} ?: ""
				FrostSignScreen(
					round = 1,
					publicKeyPackageHex = pkg,
					walletIdHint = json.optString("walletId", ""),
					alphasJson = json.optJSONArray("alphas")?.toString() ?: "[]",
					summary = summaryText,
					sighashHex = json.optString("sighash", ""),
					pcztHex = json.optString("pczt", ""),
					onNoncesUpdated = { noncesArr, k, seed ->
						scanViewModel.frostSignNoncesPerAction = noncesArr
						scanViewModel.frostSignKeyPackage = k
						scanViewModel.frostSignEphemeralSeed = seed
					},
					onScanNext = scanNextFrost,
					modifier = Modifier.statusBarsPadding(),
					onDone = { dismissFrost(); scanViewModel.clearFrostSignState() },
				)
			}
			"sign2" -> {
				FrostSignScreen(
					round = 2,
					publicKeyPackageHex = json.optString("publicKeyPackage", ""),
					sighashHex = json.optString("sighash", ""),
					alphasJson = json.optJSONArray("alphas")?.toString() ?: "[]",
					bundledCommitmentsJson = json.optJSONArray("bundledCommitments")?.toString() ?: "[]",
					previousNoncesPerAction = scanViewModel.frostSignNoncesPerAction,
					previousKeyPackage = scanViewModel.frostSignKeyPackage,
					previousEphemeralSeed = scanViewModel.frostSignEphemeralSeed,
					onNoncesUpdated = { noncesArr, k, seed ->
						scanViewModel.frostSignNoncesPerAction = noncesArr
						scanViewModel.frostSignKeyPackage = k
						scanViewModel.frostSignEphemeralSeed = seed
					},
					onScanNext = scanNextFrost,
					modifier = Modifier.statusBarsPadding(),
					onDone = { dismissFrost(); scanViewModel.clearFrostSignState() },
				)
			}
			else -> {
				scanViewModel.frostPayload.value = null
			}
		}
	} else if (scanViewModel.authPayload.collectAsStateWithLifecycle().value != null) {
		val authJson = scanViewModel.authPayload.collectAsStateWithLifecycle().value!!
		var seedPhrase by remember { mutableStateOf("") }
		LaunchedEffect(authJson) {
			seedPhrase = scanViewModel.getFirstSeedPhrase()
		}
		if (seedPhrase.isNotEmpty()) {
			AuthChallengeScreen(
				domain = authJson.optString("domain", ""),
				nonce = authJson.optString("nonce", ""),
				timestamp = authJson.optLong("ts", 0).toULong(),
				seedPhrase = seedPhrase,
				modifier = Modifier.statusBarsPadding(),
				onDone = { scanViewModel.authPayload.value = null },
			)
		}
	} else if (scanViewModel.zidSignPayload.collectAsStateWithLifecycle().value != null) {
		val zidJson = scanViewModel.zidSignPayload.collectAsStateWithLifecycle().value!!
		ZidSignScreen(
			qrJson = zidJson,
			getSeedPhrase = { scanViewModel.getFirstSeedPhrase() },
			modifier = Modifier.statusBarsPadding(),
			onDone = { scanViewModel.zidSignPayload.value = null },
		)
	} else if (zcashNoteSyncResult.value != null) {
		ZcashNoteSyncScreen(
			result = zcashNoteSyncResult.value!!,
			modifier = Modifier.statusBarsPadding(),
			onDone = {
				scanViewModel.clearZcashNoteSyncState()
			}
		)
	} else if (urBackupData != null) {
		BackupRestoreSubgraph(
			urFrames = urBackupData,
			onClose = {
				backAction()
			},
			onSuccess = { seedName ->
				Toast.makeText(
					context,
					context.getString(
						R.string.backup_restore_success_toast,
						seedName
					),
					Toast.LENGTH_LONG
				).show()
				scanViewModel.clearState()
				openKeySet(seedName)
			},
			onError = { error ->
				scanViewModel.transactionError.value =
					LocalErrorSheetModel(context = context, details = error)
				scanViewModel.urBackupFrames.value = null
			},
		)
	} else if (bananaQrData != null) {
		BananaSplitSubgraph(
			qrData = bananaQrData,
			onClose = {
				backAction()
			},
			onSuccess = { seedName ->
				Toast.makeText(
					context,
					context.getString(
						R.string.key_set_has_been_recovered_toast,
						seedName
					),
					Toast.LENGTH_LONG
				).show()
				scanViewModel.clearState()
				openKeySet(seedName)
			},
			onCustomError = { error ->
				scanViewModel.transactionError.value =
					LocalErrorSheetModel(context = context, details = error)
				scanViewModel.bananaSplitPassword.value = null
			},
			suggestedSeedName = seedNameSuggestion,
			onErrorWrongPassword = {
				scanViewModel.errorWrongPassword.value = true
				scanViewModel.bananaSplitPassword.value = null
			},
		)
	} else if (dynamicDerivationsData != null) {
		AddDynamicDerivationScreenFull(
			model = dynamicDerivationsData,
			onClose = scanViewModel::clearState,
		)
	} else if (unifiedSignatureResult.value != null) {
		// Unified signature QR display
		UnifiedSignatureQrScreen(
			result = unifiedSignatureResult.value!!,
			modifier = Modifier.statusBarsPadding(),
			onDone = {
				scanViewModel.clearSignState()
			}
		)
	} else if (unifiedSignRequest.value != null) {
		// Unified transaction screen (currently for zcash simple sign)
		UnifiedTransactionScreen(
			signRequest = unifiedSignRequest.value!!,
			modifier = Modifier.statusBarsPadding(),
			onApprove = {
				scanViewModel.signUnifiedTransaction(context)
			},
			onDecline = {
				scanViewModel.clearSignState()
			}
		)
	} else if (transactionsValue == null || showingModals) {

		ScanScreen(
			onClose = onCloseCamera,
			performPayloads = { payloads ->
				scanViewModel.performTransactionPayload(payloads, context)
			},
			onBananaSplit = { payloads ->
				scanViewModel.bananaSplitPassword.value = payloads
			},
			onDynamicDerivations = { payload ->
				scanViewModel.performDynamicDerivationPayload(payload, context)
			},
			onDynamicDerivationsTransactions = { payload ->
				scanViewModel.performDynamicDerivationTransaction(payload, context)
			},
			onPenumbraSignRequest = { payload ->
				scanViewModel.performUnifiedSignRequest(payload, context)
			},
			onCosmosSignRequest = { payload ->
				scanViewModel.performUnifiedSignRequest(payload, context)
			},
			onZcashSimpleSign = { payload ->
				scanViewModel.performUnifiedSignRequest(payload, context)
			},
			onUrBackupRestore = { urFrames ->
				scanViewModel.urBackupFrames.value = urFrames
			},
			onZcashNotes = { urFrames ->
				scanViewModel.performZcashNoteSync(urFrames, context)
			},
			onZcashPczt = { urParts ->
				scanViewModel.zcashPcztUrParts.value = urParts
			},
			onFrost = { json ->
				scanViewModel.frostPayload.value = json
			},
			onAuth = { json ->
				scanViewModel.authPayload.value = json
			},
			onZidSign = { json ->
				scanViewModel.zidSignPayload.value = json
			},
		)
	} else {

		TransactionsScreenFull(
			transactions = transactionsValue.transactions,
			signature = signature.value,
			modifier = Modifier.statusBarsPadding(),
			onBack = {
				FakeNavigator().backAction()
				scanViewModel.clearState()
			},
			onApprove = {
				when (val previewType =
					transactions.value?.transactions?.previewType) {
					is TransactionPreviewType.AddNetwork -> {
						Toast.makeText(
							context,
							context.getString(
								R.string.toast_network_added,
								previewType.network
							),
							Toast.LENGTH_LONG
						).show()
						addedNetworkName.value = previewType.network
					}

					is TransactionPreviewType.Metadata -> {
						Toast.makeText(
							context,
							context.getString(
								R.string.toast_metadata_added,
								previewType.network,
								previewType.version
							),
							Toast.LENGTH_LONG
						).show()
					}

					else -> {
						//nothing
					}
				}
				//finally clear transaction state and stay in scan screen
				scanViewModel.clearState()
				val fakeNavigator = FakeNavigator()
				fakeNavigator.navigate(Action.GO_FORWARD)
				fakeNavigator.navigate(Action.START)
				fakeNavigator.navigate(Action.NAVBAR_SCAN)
			},
			onImportKeys = {
				scanViewModel.onImportKeysTap(transactionsValue, context)
			}
		)
	}
	//Bottom sheets
	transactionError.value?.let { presentableErrorValue ->
		BottomSheetWrapperRoot(onClosedAction = scanViewModel::clearState) {
			LocalErrorBottomSheet(
				error = presentableErrorValue,
				onOk = scanViewModel::clearState,
			)
		}
	} ?: passwordModel.value?.let { passwordModelValue ->
		BottomSheetWrapperRoot(onClosedAction = {
			scanViewModel.resetRustModalToNewScan()
			scanViewModel.clearState()
		}) {
			EnterPassword(
				data = passwordModelValue,
				proceed = { password ->
					scanViewModel.viewModelScope.launch {
						scanViewModel.handlePasswordEntered(password)
					}
				},
				onClose = {
					scanViewModel.resetRustModalToNewScan()
					scanViewModel.clearState()
				},
			)
		}
	} ?: addedNetworkName.value?.let { addedNetwork ->
		AddedNetworkSheetsSubgraph(
			networkNameAdded = addedNetwork,
			onClose = {
				addedNetworkName.value = null
			}
		)
	} ?: if (errorWrongPassword.value) {
		BottomSheetWrapperRoot(onClosedAction = scanViewModel::clearState) {
			WrongPasswordBottomSheet(
				onOk = scanViewModel::clearState
			)
		}
	} else {
		//no bottom sheet
	}
}


