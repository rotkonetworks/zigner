package net.rotko.zigner.screens.scan

import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
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
import net.rotko.zigner.screens.scan.transaction.ZcashTransactionScreen
import net.rotko.zigner.screens.scan.transaction.PenumbraTransactionScreen
import net.rotko.zigner.screens.scan.transaction.PenumbraSignatureQrScreen
import net.rotko.zigner.screens.scan.transaction.CosmosTransactionScreen
import net.rotko.zigner.screens.scan.transaction.CosmosSignatureQrScreen
import net.rotko.zigner.screens.scan.transaction.dynamicderivations.AddDynamicDerivationScreenFull
import net.rotko.zigner.screens.scan.transaction.previewType
import net.rotko.zigner.screens.scan.transaction.ZcashSignatureQrScreen
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

	// Zcash signing state
	val zcashSignRequest = scanViewModel.zcashSignRequest.collectAsStateWithLifecycle()
	val zcashSignatureQr = scanViewModel.zcashSignatureQr.collectAsStateWithLifecycle()

	// Penumbra signing state
	val penumbraSignRequest = scanViewModel.penumbraSignRequest.collectAsStateWithLifecycle()
	val penumbraSignatureQr = scanViewModel.penumbraSignatureQr.collectAsStateWithLifecycle()

	// Cosmos signing state
	val cosmosSignRequest = scanViewModel.cosmosSignRequest.collectAsStateWithLifecycle()
	val cosmosSignatureQr = scanViewModel.cosmosSignatureQr.collectAsStateWithLifecycle()

	// UR backup restore state
	val urBackupFrames = scanViewModel.urBackupFrames.collectAsStateWithLifecycle()

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

	if (urBackupData != null) {
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
	} else if (zcashSignatureQr.value != null) {
		// Show Zcash signature QR after signing
		ZcashSignatureQrScreen(
			signatureBytes = zcashSignatureQr.value!!,
			modifier = Modifier.statusBarsPadding(),
			onDone = {
				scanViewModel.clearZcashState()
			}
		)
	} else if (zcashSignRequest.value != null) {
		// Show Zcash transaction for approval
		ZcashTransactionScreen(
			request = zcashSignRequest.value!!,
			modifier = Modifier.statusBarsPadding(),
			onApprove = {
				scanViewModel.viewModelScope.launch {
					scanViewModel.signZcashTransaction(context)
				}
			},
			onDecline = {
				scanViewModel.clearZcashState()
			}
		)
	} else if (cosmosSignatureQr.value != null) {
		// Show Cosmos signature QR after signing
		CosmosSignatureQrScreen(
			signatureBytes = cosmosSignatureQr.value!!,
			modifier = Modifier.statusBarsPadding(),
			onDone = {
				scanViewModel.clearCosmosState()
			}
		)
	} else if (cosmosSignRequest.value != null) {
		// Show Cosmos transaction for approval
		CosmosTransactionScreen(
			request = cosmosSignRequest.value!!,
			modifier = Modifier.statusBarsPadding(),
			onApprove = {
				scanViewModel.viewModelScope.launch {
					scanViewModel.signCosmosTransaction(context)
				}
			},
			onDecline = {
				scanViewModel.clearCosmosState()
			}
		)
	} else if (penumbraSignatureQr.value != null) {
		// Show Penumbra signature QR after signing
		PenumbraSignatureQrScreen(
			signatureBytes = penumbraSignatureQr.value!!,
			modifier = Modifier.statusBarsPadding(),
			onDone = {
				scanViewModel.clearPenumbraState()
			}
		)
	} else if (penumbraSignRequest.value != null) {
		// Show Penumbra transaction for approval
		PenumbraTransactionScreen(
			request = penumbraSignRequest.value!!,
			modifier = Modifier.statusBarsPadding(),
			onApprove = {
				scanViewModel.signPenumbraTransaction(context)
			},
			onDecline = {
				scanViewModel.clearPenumbraState()
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
			onZcashSignRequest = { payload ->
				scanViewModel.performZcashSignRequest(payload, context)
			},
			onPenumbraSignRequest = { payload ->
				scanViewModel.performPenumbraSignRequest(payload, context)
			},
			onCosmosSignRequest = { payload ->
				scanViewModel.performCosmosSignRequest(payload, context)
			},
			onUrBackupRestore = { urFrames ->
				scanViewModel.urBackupFrames.value = urFrames
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


