package net.rotko.zigner.screens.scan.transaction

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material.CircularProgressIndicator
import androidx.compose.material.Icon
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.components.qrcode.AnimatedQrKeysInfo
import net.rotko.zigner.components.qrcode.EmptyQrCodeProvider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*
import io.parity.signer.uniffi.frostSignRound1
import io.parity.signer.uniffi.frostSpendSignRound2
import io.parity.signer.uniffi.frostListWallets
import io.parity.signer.uniffi.frostLoadWallet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber

/**
 * FROST signing — zigner-mediated airgap multisig spend.
 *
 * Round 1: triggered by {"frost":"sign1","publicKeyPackage":"...","sighash":"...","alphas":[...],"summary":{...}}
 *   → match wallet by public_key_package → generate per-action nonces+commitments
 *   → display {"frost":"sign1-resp","commitments":[...]} QR
 *   → "Scan Round 2" → back to camera; nonces[] + key_package saved in ScanViewModel.
 *
 * Round 2: triggered by {"frost":"sign2","publicKeyPackage":"...","sighash":"...","alphas":[...],"bundledCommitments":[[...]]}
 *   → for each action i: spend_sign_round2(key_pkg, nonces[i], sighash, alphas[i], bundledCommitments[i])
 *   → display {"frost":"sign2-resp","shares":[...]} QR → done.
 */

enum class FrostSignState {
	LOADING,
	DISPLAY_QR,
	ERROR,
}

@Composable
fun FrostSignScreen(
	round: Int,  // 1 or 2
	publicKeyPackageHex: String = "",
	// Round 1 inputs (alphas length tells us how many actions to commit to)
	alphasJson: String = "[]",
	summary: String = "",
	// Round 2 inputs
	sighashHex: String = "",
	bundledCommitmentsJson: String = "[]",
	// Shared state from previous round
	previousNoncesPerAction: List<String> = emptyList(),
	previousKeyPackage: String = "",
	onNoncesUpdated: (noncesPerAction: List<String>, keyPackage: String) -> Unit = { _, _ -> },
	onScanNext: Callback,
	onDone: Callback,
	modifier: Modifier = Modifier,
) {
	val scope = rememberCoroutineScope()

	var state by remember { mutableStateOf(FrostSignState.LOADING) }
	var errorMsg by remember { mutableStateOf("") }
	var qrData by remember { mutableStateOf("") }

	LaunchedEffect(Unit) {
		Timber.d("[FROST] FrostSignScreen round=$round pkg=…${publicKeyPackageHex.takeLast(8)}")
		scope.launch {
			try {
				when (round) {
					1 -> {
						// match wallet by public_key_package
						val wallets = withContext(Dispatchers.Default) { frostListWallets() }
						val match = wallets.firstOrNull { w ->
							runCatching {
								val w2json = withContext(Dispatchers.Default) { frostLoadWallet(w.walletId) }
								org.json.JSONObject(w2json).getString("public_key_package") == publicKeyPackageHex
							}.getOrDefault(false)
						} ?: throw IllegalStateException(
							"no FROST wallet matches the requested public key package — was it stored on this device?"
						)
						Timber.d("[FROST] sign1 matched wallet=${match.walletId}")
						val walletJson = withContext(Dispatchers.Default) { frostLoadWallet(match.walletId) }
						val wallet = org.json.JSONObject(walletJson)
						val keyPackageHex = wallet.getString("key_package")
						val ephemeralSeedHex = wallet.getString("ephemeral_seed")

						// fresh round-1 commitment+nonce per action
						val alphas = org.json.JSONArray(alphasJson)
						val noncesArr = mutableListOf<String>()
						val commitmentsArr = mutableListOf<String>()
						for (i in 0 until alphas.length()) {
							val r1 = withContext(Dispatchers.Default) {
								frostSignRound1(ephemeralSeedHex, keyPackageHex)
							}
							val r1json = org.json.JSONObject(r1)
							noncesArr.add(r1json.getString("nonces"))
							commitmentsArr.add(r1json.getString("commitments"))
						}
						onNoncesUpdated(noncesArr, keyPackageHex)
						qrData = org.json.JSONObject().apply {
							put("frost", "sign1-resp")
							put("commitments", org.json.JSONArray(commitmentsArr))
						}.toString()
						state = FrostSignState.DISPLAY_QR
					}
					2 -> {
						val alphas = org.json.JSONArray(alphasJson)
						val bundled = org.json.JSONArray(bundledCommitmentsJson)
						if (alphas.length() != bundled.length() || alphas.length() != previousNoncesPerAction.size) {
							throw IllegalStateException(
								"action count mismatch: alphas=${alphas.length()} bundled=${bundled.length()} nonces=${previousNoncesPerAction.size}"
							)
						}
						val sharesArr = mutableListOf<String>()
						for (i in 0 until alphas.length()) {
							val alphaHex = alphas.getString(i)
							val perActionCommitsJson = bundled.getJSONArray(i).toString()
							val share = withContext(Dispatchers.Default) {
								frostSpendSignRound2(
									previousKeyPackage,
									previousNoncesPerAction[i],
									sighashHex,
									alphaHex,
									perActionCommitsJson,
								)
							}
							sharesArr.add(share)
						}
						onNoncesUpdated(emptyList(), "")  // clear after use
						qrData = org.json.JSONObject().apply {
							put("frost", "sign2-resp")
							put("shares", org.json.JSONArray(sharesArr))
						}.toString()
						state = FrostSignState.DISPLAY_QR
					}
				}
			} catch (e: Exception) {
				Timber.e(e, "[FROST] sign round $round failed")
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
		Row(verticalAlignment = Alignment.CenterVertically) {
			Text(
				text = if (round == 1) "FROST Sign — Round 1 (commitments)" else "FROST Sign — Round 2 (shares)",
				style = SignerTypeface.TitleL,
				color = MaterialTheme.colors.primary,
				modifier = Modifier.weight(1f)
			)
			if (state != FrostSignState.ERROR) {
				DontQuitIcon(message = "don't leave this screen — quitting cancels signing")
			}
		}
		if (round == 1 && summary.isNotEmpty()) {
			Text(
				text = summary,
				style = SignerTypeface.CaptionM,
				color = MaterialTheme.colors.textTertiary,
				modifier = Modifier.padding(top = 4.dp, bottom = 8.dp)
			)
		} else {
			Spacer(modifier = Modifier.height(8.dp))
		}

		when (state) {
			FrostSignState.LOADING -> {
				Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
					Column(horizontalAlignment = Alignment.CenterHorizontally) {
						CircularProgressIndicator(color = MaterialTheme.colors.pink500, modifier = Modifier.size(48.dp))
						Spacer(modifier = Modifier.height(16.dp))
						Text(
							if (round == 1) "Generating commitments..." else "Computing shares...",
							style = SignerTypeface.TitleS, color = MaterialTheme.colors.primary,
						)
					}
				}
			}

			FrostSignState.DISPLAY_QR -> {
				Text(
					text = if (round == 1) "Show this to zafu — round 1 commitments"
						   else "Show this to zafu — round 2 shares",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp)
				)
				val frames: List<List<UByte>>? = remember(qrData) {
					try {
						val raw = qrData.toByteArray(Charsets.UTF_8)
						val b64 = android.util.Base64.encodeToString(raw, android.util.Base64.NO_WRAP)
						val chunkSize = 400 // matches zafu DEFAULT_CHUNK_SIZE
						val totalChunks = ((b64.length + chunkSize - 1) / chunkSize).coerceAtLeast(1)
						Timber.d("[FROST] sign frames round=$round rawBytes=${raw.size} b64Len=${b64.length} totalChunks=$totalChunks")
						(0 until totalChunks).map { i ->
							val chunk = b64.substring(i * chunkSize, minOf((i + 1) * chunkSize, b64.length))
							val frameStr = "P${i + 1}/$totalChunks/zafu-frost-sign/$chunk"
							frameStr.toByteArray(Charsets.UTF_8).map { it.toUByte() }
						}
					} catch (e: Exception) {
						Timber.e(e, "[FROST] sign frames prep failed round=$round inputLen=${qrData.length}")
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
							modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp),
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
				if (round == 1) {
					Text(
						text = "After zafu collects peer commitments, scan the round-2 trigger QR",
						style = SignerTypeface.CaptionM,
						color = MaterialTheme.colors.textTertiary,
						modifier = Modifier.padding(bottom = 8.dp)
					)
					PrimaryButtonWide(label = "Scan Round 2", onClicked = onScanNext)
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

/** Small amber warning triangle. Tap shows a Toast with the full message —
 *  Android equivalent of zafu's hover-tooltip. Reused by DKG + Sign screens. */
@Composable
internal fun DontQuitIcon(message: String) {
	val ctx = LocalContext.current
	Icon(
		imageVector = Icons.Default.Warning,
		contentDescription = message,
		tint = MaterialTheme.colors.red400,
		modifier = Modifier
			.size(18.dp)
			.clickable { Toast.makeText(ctx, message, Toast.LENGTH_SHORT).show() }
	)
}
