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
import io.parity.signer.uniffi.frostDkgPart1
import io.parity.signer.uniffi.frostDkgPart2
import io.parity.signer.uniffi.frostDkgPart3
import io.parity.signer.uniffi.frostStoreWallet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber

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
 * Round 3: triggered by {"frost":"dkg3"} → compute with saved secret → store wallet
 *   → display r3 ack QR with public_key_package so zafu can derive UFVK → done
 */

enum class DkgState {
	COMPUTING,
	DISPLAY_QR,
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
		Timber.d("[FROST] FrostDkgScreen round=$round t=$minSigners n=$maxSigners label='$label' mainnet=$mainnet")
		scope.launch {
			try {
				when (round) {
					1 -> {
						Timber.d("[FROST] calling frostDkgPart1($maxSigners, $minSigners)")
						val result = withContext(Dispatchers.Default) {
							frostDkgPart1(maxSigners, minSigners)
						}
						Timber.d("[FROST] frostDkgPart1 returned ${result.length} chars")
						val json = org.json.JSONObject(result)
						onSecretUpdated(json.getString("secret"))
						qrData = json.getString("broadcast")
						Timber.d("[FROST] r1 broadcast hex length=${qrData.length}")
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
						val pkg = json.getString("public_key_package")
						val wid = withContext(Dispatchers.Default) {
							frostStoreWallet(
								json.getString("key_package"),
								pkg,
								json.getString("ephemeral_seed"),
								label, minSigners, maxSigners, mainnet
							)
						}
						walletId = wid
						onSecretUpdated("") // clear secret
						// emit r3 ack so zafu can derive UFVK + address from public_key_package
						qrData = org.json.JSONObject().apply {
							put("frost", "r3")
							put("public_key_package", pkg)
							put("wallet_id", wid)
						}.toString()
						state = DkgState.DISPLAY_QR
					}
				}
			} catch (e: Exception) {
				Timber.e(e, "[FROST] DKG round $round failed")
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
		Row(verticalAlignment = Alignment.CenterVertically) {
			Text(
				text = "FROST DKG — Round $round of 3",
				style = SignerTypeface.TitleL,
				color = MaterialTheme.colors.primary,
				modifier = Modifier.weight(1f)
			)
			if (state != DkgState.ERROR) {
				DontQuitIcon(message = "don't leave this screen — quitting cancels DKG")
			}
		}
		Text(
			text = "${minSigners}-of-${maxSigners} multisig",
			style = SignerTypeface.BodyL,
			color = MaterialTheme.colors.textSecondary,
			modifier = Modifier.padding(top = 4.dp, bottom = 16.dp)
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
					text = if (round == 3) "Key share stored — show this to zafu"
					       else "Show this to the coordinator",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp)
				)
				// Split the payload into P-frame chunks the way zafu's
				// AnimatedQrDisplay/Scanner expect: P<idx>/<total>/<urType>/<base64>.
				// Each frame fits well under the single-QR cap; the receiver
				// reassembles in order.
				val frames: List<List<UByte>>? = remember(qrData) {
					try {
						val isHex = qrData.length % 2 == 0 && qrData.matches(Regex("^[0-9a-fA-F]+$"))
						val raw: ByteArray = if (isHex) {
							ByteArray(qrData.length / 2) { i ->
								qrData.substring(i * 2, i * 2 + 2).toInt(16).toByte()
							}
						} else {
							qrData.toByteArray(Charsets.UTF_8)
						}
						val b64 = android.util.Base64.encodeToString(raw, android.util.Base64.NO_WRAP)
						val chunkSize = 400 // matches zafu's DEFAULT_CHUNK_SIZE
						val totalChunks = ((b64.length + chunkSize - 1) / chunkSize).coerceAtLeast(1)
						Timber.d("[FROST] frames prepared round=$round rawBytes=${raw.size} b64Len=${b64.length} totalChunks=$totalChunks isHex=$isHex")
						(0 until totalChunks).map { i ->
							val chunk = b64.substring(i * chunkSize, minOf((i + 1) * chunkSize, b64.length))
							val frameStr = "P${i + 1}/$totalChunks/zafu-frost-dkg/$chunk"
							frameStr.toByteArray(Charsets.UTF_8).map { it.toUByte() }
						}
					} catch (e: Exception) {
						Timber.e(e, "[FROST] frames prep failed for round=$round inputLen=${qrData.length}")
						null
					}
				}
				Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
					when {
						frames == null -> Text(
							"failed to prepare QR payload",
							style = SignerTypeface.BodyL,
							color = MaterialTheme.colors.red500,
						)
						else -> AnimatedQrKeysInfo<List<List<UByte>>>(
							input = frames,
							provider = EmptyQrCodeProvider(),
							modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp)
						)
					}
				}
				if (frames != null && frames.size > 1) {
					Spacer(modifier = Modifier.height(4.dp))
					Text(
						text = "${frames.size} frames cycling — let zafu scan one full cycle",
						style = SignerTypeface.CaptionM,
						color = MaterialTheme.colors.textTertiary,
					)
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
					Text(
						text = "Wallet $walletId saved. Tap Done after zafu confirms it scanned the QR.",
						style = SignerTypeface.CaptionM,
						color = MaterialTheme.colors.textTertiary,
						modifier = Modifier.padding(bottom = 8.dp)
					)
					PrimaryButtonWide(label = "Done", onClicked = onDone)
				}
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
