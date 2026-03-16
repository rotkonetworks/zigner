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
import io.parity.signer.uniffi.frostSignRound1
import io.parity.signer.uniffi.frostSpendSignActions
import io.parity.signer.uniffi.frostLoadWallet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * FROST signing flow — 2 rounds:
 *
 * Round 1 (commitment): Triggered by scan of sign-init QR.
 *   Load wallet → frost_sign_round1 → display commitments QR
 *
 * Round 2 (sign): Triggered by scan of sign-request QR.
 *   frost_spend_sign_actions → display shares QR
 */

enum class FrostSignState {
	LOADING_WALLET,
	GENERATING_COMMITMENTS,
	DISPLAY_COMMITMENTS,
	SIGNING,
	DISPLAY_SHARES,
	ERROR,
}

@Composable
fun FrostSignScreen(
	walletId: String,
	// Round 2 data (null if we're only doing round 1)
	sighashHex: String? = null,
	alphasJson: String? = null,
	commitmentsJson: String? = null,
	onDone: Callback,
	modifier: Modifier = Modifier,
) {
	val scope = rememberCoroutineScope()

	var state by remember { mutableStateOf(FrostSignState.LOADING_WALLET) }
	var errorMsg by remember { mutableStateOf("") }
	var commitmentsQr by remember { mutableStateOf("") }
	var sharesQr by remember { mutableStateOf("") }
	var noncesHex by remember { mutableStateOf("") }

	// Determine if this is round 1 (generate commitments) or round 2 (sign)
	val isRound2 = sighashHex != null && alphasJson != null && commitmentsJson != null

	LaunchedEffect(Unit) {
		scope.launch {
			try {
				// Load wallet secrets
				state = FrostSignState.LOADING_WALLET
				val walletJson = withContext(Dispatchers.Default) {
					frostLoadWallet(walletId)
				}
				val wallet = org.json.JSONObject(walletJson)
				val keyPackageHex = wallet.getString("key_package")
				val ephemeralSeedHex = wallet.getString("ephemeral_seed")

				if (isRound2) {
					// Round 2: sign with provided nonces (from previous round 1)
					// For now, we need nonces from the previous round which should have
					// been stored. In the QR flow, the coordinator includes them.
					state = FrostSignState.SIGNING
					val result = withContext(Dispatchers.Default) {
						frostSpendSignActions(
							keyPackageHex, noncesHex, sighashHex!!, alphasJson!!, commitmentsJson!!
						)
					}
					sharesQr = result
					state = FrostSignState.DISPLAY_SHARES
				} else {
					// Round 1: generate commitments
					state = FrostSignState.GENERATING_COMMITMENTS
					val result = withContext(Dispatchers.Default) {
						frostSignRound1(ephemeralSeedHex, keyPackageHex)
					}
					val json = org.json.JSONObject(result)
					noncesHex = json.getString("nonces")
					commitmentsQr = json.getString("commitments")
					state = FrostSignState.DISPLAY_COMMITMENTS
				}
			} catch (e: Exception) {
				errorMsg = e.message ?: "FROST signing failed"
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
			text = "FROST Sign",
			style = SignerTypeface.TitleL,
			color = MaterialTheme.colors.primary,
			modifier = Modifier.padding(bottom = 16.dp)
		)

		when (state) {
			FrostSignState.LOADING_WALLET,
			FrostSignState.GENERATING_COMMITMENTS,
			FrostSignState.SIGNING -> {
				val msg = when (state) {
					FrostSignState.LOADING_WALLET -> "Loading wallet..."
					FrostSignState.GENERATING_COMMITMENTS -> "Generating commitments..."
					else -> "Signing..."
				}
				Box(
					modifier = Modifier.weight(1f).fillMaxWidth(),
					contentAlignment = Alignment.Center
				) {
					Column(horizontalAlignment = Alignment.CenterHorizontally) {
						CircularProgressIndicator(
							color = MaterialTheme.colors.pink500,
							modifier = Modifier.size(48.dp)
						)
						Spacer(modifier = Modifier.height(16.dp))
						Text(text = msg, style = SignerTypeface.TitleS, color = MaterialTheme.colors.primary)
					}
				}
			}

			FrostSignState.DISPLAY_COMMITMENTS -> {
				Text(
					text = "Show this commitment to the coordinator",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp)
				)
				QrDisplayText(
					data = commitmentsQr,
					modifier = Modifier.weight(1f)
				)
				SignerDivider()
				Spacer(modifier = Modifier.height(8.dp))
				Text(
					text = "After coordinator collects all commitments, scan the sign request QR",
					style = SignerTypeface.CaptionM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp)
				)
				PrimaryButtonWide(label = "Done", onClicked = onDone)
			}

			FrostSignState.DISPLAY_SHARES -> {
				Text(
					text = "Show this signature share to the coordinator",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp)
				)
				QrDisplayText(
					data = sharesQr,
					modifier = Modifier.weight(1f)
				)
				SignerDivider()
				Spacer(modifier = Modifier.height(16.dp))
				PrimaryButtonWide(label = "Done", onClicked = onDone)
			}

			FrostSignState.ERROR -> {
				Box(
					modifier = Modifier.weight(1f).fillMaxWidth(),
					contentAlignment = Alignment.Center
				) {
					Column(horizontalAlignment = Alignment.CenterHorizontally) {
						Text(
							text = "Signing Failed",
							style = SignerTypeface.TitleS,
							color = MaterialTheme.colors.red500
						)
						Spacer(modifier = Modifier.height(8.dp))
						Text(
							text = errorMsg,
							style = SignerTypeface.BodyL,
							color = MaterialTheme.colors.textSecondary
						)
					}
				}
				SignerDivider()
				Spacer(modifier = Modifier.height(16.dp))
				SecondaryButtonWide(label = "Dismiss", onClicked = onDone)
			}
		}
	}
}

@Composable
private fun QrDisplayText(data: String, modifier: Modifier = Modifier) {
	val qrBytes = remember(data) {
		try {
			val bytes = data.toByteArray(Charsets.UTF_8).map { it.toUByte() }
			kotlinx.coroutines.runBlocking { encodeToQr(bytes, false) }
		} catch (e: Exception) { null }
	}
	Box(
		modifier = modifier.fillMaxWidth(),
		contentAlignment = Alignment.Center
	) {
		if (qrBytes != null) {
			AnimatedQrKeysInfo<List<List<UByte>>>(
				input = listOf(qrBytes),
				provider = EmptyQrCodeProvider(),
				modifier = Modifier
					.fillMaxWidth()
					.padding(horizontal = 24.dp)
			)
		}
	}
}
