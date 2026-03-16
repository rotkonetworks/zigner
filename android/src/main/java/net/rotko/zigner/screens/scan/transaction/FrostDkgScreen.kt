package net.rotko.zigner.screens.scan.transaction

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.CircularProgressIndicator
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.components.qrcode.AnimatedQrKeysInfo
import net.rotko.zigner.components.qrcode.EmptyQrCodeProvider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*
import io.parity.signer.uniffi.encodeToQr
import io.parity.signer.uniffi.frostDkgPart1
import io.parity.signer.uniffi.frostDkgPart2
import io.parity.signer.uniffi.frostDkgPart3
import io.parity.signer.uniffi.frostStoreWallet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

/**
 * FROST DKG — handles one round at a time.
 *
 * Round 1: triggered by {"frost":"dkg1"} → compute → display broadcast QR
 *   → user shows QR to coordinator → taps "Scan Next" → back to camera
 *   → DKG secret saved in ScanViewModel.frostDkgSecret
 *
 * Round 2: triggered by {"frost":"dkg2"} → compute with saved secret → display packages QR
 *   → user shows QR to coordinator → taps "Scan Next" → back to camera
 *
 * Round 3: triggered by {"frost":"dkg3"} → compute with saved secret → store wallet → done
 */

enum class DkgState {
	COMPUTING,
	DISPLAY_QR,
	COMPLETE,
	ERROR,
}

@Composable
fun FrostDkgScreen(
	round: Int,  // 1, 2, or 3
	maxSigners: UShort,
	minSigners: UShort,
	label: String,
	mainnet: Boolean,
	// Round 2/3 data from coordinator QR
	broadcastsJson: String = "[]",
	round1BroadcastsJson: String = "[]",
	round2PackagesJson: String = "[]",
	// Shared state: DKG secret from previous round
	previousSecret: String = "",
	onSecretUpdated: (String) -> Unit = {},
	onScanNext: Callback,
	onDone: Callback,
	modifier: Modifier = Modifier,
) {
	val scope = rememberCoroutineScope()

	var state by remember { mutableStateOf(DkgState.COMPUTING) }
	var errorMsg by remember { mutableStateOf("") }
	var qrData by remember { mutableStateOf("") }
	var walletId by remember { mutableStateOf("") }

	LaunchedEffect(Unit) {
		scope.launch {
			try {
				when (round) {
					1 -> {
						val result = withContext(Dispatchers.Default) {
							frostDkgPart1(maxSigners, minSigners)
						}
						val json = org.json.JSONObject(result)
						onSecretUpdated(json.getString("secret"))
						qrData = json.getString("broadcast")
						state = DkgState.DISPLAY_QR
					}
					2 -> {
						val result = withContext(Dispatchers.Default) {
							frostDkgPart2(previousSecret, broadcastsJson)
						}
						val json = org.json.JSONObject(result)
						onSecretUpdated(json.getString("secret"))
						// Peer packages as JSON array for display
						qrData = json.getJSONArray("peer_packages").toString()
						state = DkgState.DISPLAY_QR
					}
					3 -> {
						val result = withContext(Dispatchers.Default) {
							frostDkgPart3(previousSecret, round1BroadcastsJson, round2PackagesJson)
						}
						val json = org.json.JSONObject(result)
						val wid = withContext(Dispatchers.Default) {
							frostStoreWallet(
								json.getString("key_package"),
								json.getString("public_key_package"),
								json.getString("ephemeral_seed"),
								label, minSigners, maxSigners, mainnet
							)
						}
						walletId = wid
						onSecretUpdated("") // clear secret
						state = DkgState.COMPLETE
					}
				}
			} catch (e: Exception) {
				errorMsg = e.message ?: "DKG round $round failed"
				state = DkgState.ERROR
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
			text = "FROST DKG — Round $round of 3",
			style = SignerTypeface.TitleL,
			color = MaterialTheme.colors.primary,
			modifier = Modifier.padding(bottom = 4.dp)
		)
		Text(
			text = "${minSigners}-of-${maxSigners} multisig",
			style = SignerTypeface.BodyL,
			color = MaterialTheme.colors.textSecondary,
			modifier = Modifier.padding(bottom = 16.dp)
		)

		when (state) {
			DkgState.COMPUTING -> {
				Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
					Column(horizontalAlignment = Alignment.CenterHorizontally) {
						CircularProgressIndicator(color = MaterialTheme.colors.pink500, modifier = Modifier.size(48.dp))
						Spacer(modifier = Modifier.height(16.dp))
						Text("Computing round $round...", style = SignerTypeface.TitleS, color = MaterialTheme.colors.primary)
					}
				}
			}

			DkgState.DISPLAY_QR -> {
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
				if (round < 3) {
					Text(
						text = "After the coordinator processes this, scan the round ${round + 1} QR",
						style = SignerTypeface.CaptionM,
						color = MaterialTheme.colors.textTertiary,
						modifier = Modifier.padding(bottom = 8.dp)
					)
					PrimaryButtonWide(label = "Scan Round ${round + 1}", onClicked = onScanNext)
				} else {
					PrimaryButtonWide(label = "Done", onClicked = onDone)
				}
			}

			DkgState.COMPLETE -> {
				Column(
					modifier = Modifier.weight(1f).verticalScroll(rememberScrollState()),
					verticalArrangement = Arrangement.spacedBy(12.dp)
				) {
					Column(
						modifier = Modifier
							.fillMaxWidth()
							.clip(RoundedCornerShape(12.dp))
							.background(MaterialTheme.colors.fill6)
							.padding(16.dp),
						verticalArrangement = Arrangement.spacedBy(8.dp)
					) {
						Text("DKG Complete", style = SignerTypeface.TitleS, color = MaterialTheme.colors.primary)
						Text("Key share stored securely", style = SignerTypeface.BodyL, color = MaterialTheme.colors.textSecondary)
						Text("Wallet: $walletId", style = SignerTypeface.CaptionM, color = MaterialTheme.colors.textTertiary)
					}
				}
				SignerDivider()
				Spacer(modifier = Modifier.height(16.dp))
				PrimaryButtonWide(label = "Done", onClicked = onDone)
			}

			DkgState.ERROR -> {
				Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
					Column(horizontalAlignment = Alignment.CenterHorizontally) {
						Text("DKG Failed", style = SignerTypeface.TitleS, color = MaterialTheme.colors.red500)
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
