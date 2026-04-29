package net.rotko.zigner.screens.scan.transaction.frost

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material.CircularProgressIndicator
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.parity.signer.uniffi.frostListWallets
import io.parity.signer.uniffi.frostLoadWallet
import io.parity.signer.uniffi.frostSignRound1
import io.parity.signer.uniffi.frostSpendSignRound2
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.components.qrcode.AnimatedQrKeysInfo
import net.rotko.zigner.components.qrcode.EmptyQrCodeProvider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*
import timber.log.Timber

/**
 *  Round 1 (sign1): match wallet by public_key_package, gen per-action commitments.
 *  Round 2 (sign2): consume saved nonces + bundled commitments, emit per-action shares.
 */

enum class FrostSignState { LOADING, DISPLAY_QR, ERROR }

@Composable
fun FrostSignScreen(
	round: Int,  // 1 or 2
	publicKeyPackageHex: String = "",
	walletIdHint: String = "",  // O(1) lookup if present; falls back to pkg scan
	alphasJson: String = "[]",
	summary: String = "",
	sighashHex: String = "",
	bundledCommitmentsJson: String = "[]",
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
					1 -> runRound1(publicKeyPackageHex, walletIdHint, alphasJson, onNoncesUpdated) { qr -> qrData = qr }
					2 -> runRound2(
						sighashHex, alphasJson, bundledCommitmentsJson,
						previousNoncesPerAction, previousKeyPackage, onNoncesUpdated,
					) { qr -> qrData = qr }
				}
				state = FrostSignState.DISPLAY_QR
			} catch (e: Exception) {
				Timber.e(e, "[FROST] sign round $round failed")
				errorMsg = e.message ?: "FROST sign round $round failed"
				state = FrostSignState.ERROR
			}
		}
	}

	Column(
		modifier = modifier.fillMaxSize().background(MaterialTheme.colors.background).padding(16.dp)
	) {
		Row(verticalAlignment = Alignment.CenterVertically) {
			Text(
				text = if (round == 1) "FROST Sign — Round 1 (commitments)" else "FROST Sign — Round 2 (shares)",
				style = SignerTypeface.TitleL,
				color = MaterialTheme.colors.primary,
				modifier = Modifier.weight(1f),
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
				modifier = Modifier.padding(top = 4.dp, bottom = 8.dp),
			)
		} else {
			Spacer(modifier = Modifier.height(8.dp))
		}

		when (state) {
			FrostSignState.LOADING -> Box(
				modifier = Modifier.weight(1f).fillMaxWidth(),
				contentAlignment = Alignment.Center,
			) {
				Column(horizontalAlignment = Alignment.CenterHorizontally) {
					CircularProgressIndicator(color = MaterialTheme.colors.pink500, modifier = Modifier.size(48.dp))
					Spacer(modifier = Modifier.height(16.dp))
					Text(
						if (round == 1) "Generating commitments..." else "Computing shares...",
						style = SignerTypeface.TitleS, color = MaterialTheme.colors.primary,
					)
				}
			}

			FrostSignState.DISPLAY_QR -> {
				Text(
					text = if (round == 1) "Show this to zafu — round 1 commitments"
					       else "Show this to zafu — round 2 shares",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp),
				)
				val frames = remember(qrData) { toAnimatedQrFrames(qrData, "zafu-frost-sign") }
				Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
					if (frames == null) Text(
						"failed to prepare QR payload",
						style = SignerTypeface.BodyL,
						color = MaterialTheme.colors.red500,
					) else AnimatedQrKeysInfo<List<List<UByte>>>(
						input = frames,
						provider = EmptyQrCodeProvider(),
						modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp),
					)
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
						modifier = Modifier.padding(bottom = 8.dp),
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

/** Find wallet (O(1) via walletIdHint, else O(n) public_key_package scan), gen fresh commitments per action. */
private suspend fun runRound1(
	publicKeyPackageHex: String,
	walletIdHint: String,
	alphasJson: String,
	onNoncesUpdated: (List<String>, String) -> Unit,
	emit: (qrData: String) -> Unit,
) {
	val walletJson = if (walletIdHint.isNotEmpty()) {
		runCatching {
			val w = withContext(Dispatchers.Default) { frostLoadWallet(walletIdHint) }
			val pkg = org.json.JSONObject(w).getString("public_key_package")
			if (pkg != publicKeyPackageHex) {
				Timber.w("[FROST] walletIdHint=$walletIdHint pkg mismatch — falling back to scan")
				null
			} else {
				Timber.d("[FROST] sign1 walletIdHint hit walletId=$walletIdHint")
				w
			}
		}.getOrNull()
	} else null

	val finalJson = walletJson ?: run {
		val wallets = withContext(Dispatchers.Default) { frostListWallets() }
		val match = wallets.firstOrNull { w ->
			runCatching {
				val w2 = withContext(Dispatchers.Default) { frostLoadWallet(w.walletId) }
				org.json.JSONObject(w2).getString("public_key_package") == publicKeyPackageHex
			}.getOrDefault(false)
		} ?: throw IllegalStateException(
			"no FROST wallet matches the requested public key package — was it stored on this device?"
		)
		Timber.d("[FROST] sign1 scan-matched wallet=${match.walletId}")
		withContext(Dispatchers.Default) { frostLoadWallet(match.walletId) }
	}

	val wallet = org.json.JSONObject(finalJson)
	val keyPackage = wallet.getString("key_package")
	val ephemeralSeed = wallet.getString("ephemeral_seed")

	val alphas = org.json.JSONArray(alphasJson)
	val nonces = mutableListOf<String>()
	val commits = mutableListOf<String>()
	for (i in 0 until alphas.length()) {
		val r1 = withContext(Dispatchers.Default) { frostSignRound1(ephemeralSeed, keyPackage) }
		val j = org.json.JSONObject(r1)
		nonces.add(j.getString("nonces"))
		commits.add(j.getString("commitments"))
	}
	onNoncesUpdated(nonces, keyPackage)
	emit(org.json.JSONObject().apply {
		put("frost", "sign1-resp")
		put("commitments", org.json.JSONArray(commits))
	}.toString())
}

/** Per-action: spend_sign_round2(key_pkg, nonces[i], sighash, alphas[i], bundled[i]) → share. */
private suspend fun runRound2(
	sighashHex: String,
	alphasJson: String,
	bundledCommitmentsJson: String,
	previousNoncesPerAction: List<String>,
	previousKeyPackage: String,
	onNoncesUpdated: (List<String>, String) -> Unit,
	emit: (qrData: String) -> Unit,
) {
	val alphas = org.json.JSONArray(alphasJson)
	val bundled = org.json.JSONArray(bundledCommitmentsJson)
	require(alphas.length() == bundled.length() && alphas.length() == previousNoncesPerAction.size) {
		"action count mismatch: alphas=${alphas.length()} bundled=${bundled.length()} nonces=${previousNoncesPerAction.size}"
	}
	val shares = mutableListOf<String>()
	for (i in 0 until alphas.length()) {
		val share = withContext(Dispatchers.Default) {
			frostSpendSignRound2(
				previousKeyPackage,
				previousNoncesPerAction[i],
				sighashHex,
				alphas.getString(i),
				bundled.getJSONArray(i).toString(),
			)
		}
		shares.add(share)
	}
	onNoncesUpdated(emptyList(), "")
	emit(org.json.JSONObject().apply {
		put("frost", "sign2-resp")
		put("shares", org.json.JSONArray(shares))
	}.toString())
}
