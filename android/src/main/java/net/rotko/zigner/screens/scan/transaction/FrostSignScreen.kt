package net.rotko.zigner.screens.scan.transaction

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material.CircularProgressIndicator
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.components.qrcode.AnimatedQrKeysInfo
import net.rotko.zigner.components.qrcode.EmptyQrCodeProvider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*
import io.parity.signer.uniffi.encodeToQr
import io.parity.signer.uniffi.frostSignRound1
import io.parity.signer.uniffi.frostSpendSignActions
import io.parity.signer.uniffi.frostLoadWallet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

/**
 * FROST signing — handles one round at a time.
 *
 * Round 1: triggered by {"frost":"sign1","wallet":"..."} → load wallet → generate commitments
 *   → display commitments QR → user shows to coordinator → "Scan Sign Request" → back to camera
 *   → nonces saved in ScanViewModel.frostSignNonces
 *
 * Round 2: triggered by {"frost":"sign2","sighash":"...","alphas":[...],"commitments":[...]}
 *   → sign with saved nonces → display shares QR → done
 */

enum class FrostSignState {
	LOADING,
	DISPLAY_QR,
	ERROR,
}

@Composable
fun FrostSignScreen(
	round: Int,  // 1 or 2
	walletId: String = "",
	// Round 2 data
	sighashHex: String = "",
	alphasJson: String = "[]",
	commitmentsJson: String = "[]",
	// Shared state from previous round
	previousNonces: String = "",
	previousKeyPackage: String = "",
	onNoncesUpdated: (nonces: String, keyPackage: String) -> Unit = { _, _ -> },
	onScanNext: Callback,
	onDone: Callback,
	modifier: Modifier = Modifier,
) {
	val scope = rememberCoroutineScope()

	var state by remember { mutableStateOf(FrostSignState.LOADING) }
	var errorMsg by remember { mutableStateOf("") }
	var qrData by remember { mutableStateOf("") }
	var isRound2Complete by remember { mutableStateOf(false) }

	LaunchedEffect(Unit) {
		scope.launch {
			try {
				when (round) {
					1 -> {
						val walletJson = withContext(Dispatchers.Default) {
							frostLoadWallet(walletId)
						}
						val wallet = org.json.JSONObject(walletJson)
						val keyPackageHex = wallet.getString("key_package")
						val ephemeralSeedHex = wallet.getString("ephemeral_seed")

						val result = withContext(Dispatchers.Default) {
							frostSignRound1(ephemeralSeedHex, keyPackageHex)
						}
						val json = org.json.JSONObject(result)
						onNoncesUpdated(json.getString("nonces"), keyPackageHex)
						qrData = json.getString("commitments")
						state = FrostSignState.DISPLAY_QR
					}
					2 -> {
						val result = withContext(Dispatchers.Default) {
							frostSpendSignActions(
								previousKeyPackage, previousNonces,
								sighashHex, alphasJson, commitmentsJson
							)
						}
						qrData = result
						isRound2Complete = true
						// Clear nonces after use
						onNoncesUpdated("", "")
						state = FrostSignState.DISPLAY_QR
					}
				}
			} catch (e: Exception) {
				errorMsg = e.message ?: "FROST sign round $round failed"
				state = FrostSignState.ERROR
			}
		}
	}

	Column(
		modifier = modifier
			.fillMaxSize()
			.background(MaterialTheme.colors.background)
			.padding(16.dp)
	) {
		Text(
			text = if (round == 1) "FROST Sign — Commitments" else "FROST Sign — Shares",
			style = SignerTypeface.TitleL,
			color = MaterialTheme.colors.primary,
			modifier = Modifier.padding(bottom = 16.dp)
		)

		when (state) {
			FrostSignState.LOADING -> {
				Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
					Column(horizontalAlignment = Alignment.CenterHorizontally) {
						CircularProgressIndicator(color = MaterialTheme.colors.pink500, modifier = Modifier.size(48.dp))
						Spacer(modifier = Modifier.height(16.dp))
						Text(
							if (round == 1) "Generating commitments..." else "Signing...",
							style = SignerTypeface.TitleS, color = MaterialTheme.colors.primary
						)
					}
				}
			}

			FrostSignState.DISPLAY_QR -> {
				Text(
					text = "Show this to the coordinator",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp)
				)
				val qrBytes = remember(qrData) {
					try {
						val bytes = qrData.toByteArray(Charsets.UTF_8).map { it.toUByte() }
						runBlocking { encodeToQr(bytes, false) }
					} catch (e: Exception) { null }
				}
				Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
					if (qrBytes != null) {
						AnimatedQrKeysInfo<List<List<UByte>>>(
							input = listOf(qrBytes),
							provider = EmptyQrCodeProvider(),
							modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp)
						)
					}
				}
				SignerDivider()
				Spacer(modifier = Modifier.height(8.dp))
				if (round == 1) {
					Text(
						text = "After coordinator collects all commitments, scan the sign request QR",
						style = SignerTypeface.CaptionM,
						color = MaterialTheme.colors.textTertiary,
						modifier = Modifier.padding(bottom = 8.dp)
					)
					PrimaryButtonWide(label = "Scan Sign Request", onClicked = onScanNext)
				} else {
					PrimaryButtonWide(label = "Done", onClicked = onDone)
				}
			}

			FrostSignState.ERROR -> {
				Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
					Column(horizontalAlignment = Alignment.CenterHorizontally) {
						Text("Signing Failed", style = SignerTypeface.TitleS, color = MaterialTheme.colors.red500)
						Spacer(modifier = Modifier.height(8.dp))
						Text(errorMsg, style = SignerTypeface.BodyL, color = MaterialTheme.colors.textSecondary)
					}
				}
				SignerDivider()
				Spacer(modifier = Modifier.height(16.dp))
				SecondaryButtonWide(label = "Dismiss", onClicked = onDone)
			}
		}
	}
}
