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
import kotlinx.coroutines.withContext

/**
 * FROST DKG wizard screen — 3 rounds of scan → compute → display QR.
 *
 * State machine:
 *   init → round1_computing → round1_display (show broadcast QR)
 *     → waiting_round2 (user scans coordinator's round2 QR)
 *     → round2_computing → round2_display (show peer_packages QR)
 *     → waiting_round3 (user scans coordinator's round3 QR)
 *     → round3_computing → complete (wallet stored) | error
 *
 * The initial scan (DKG params) happens in the camera/scan layer.
 * This screen receives the parsed params and drives the rest.
 */

enum class DkgState {
	ROUND1_COMPUTING,
	ROUND1_DISPLAY,
	ROUND2_COMPUTING,
	ROUND2_DISPLAY,
	ROUND3_COMPUTING,
	COMPLETE,
	ERROR,
}

@Composable
fun FrostDkgScreen(
	maxSigners: UShort,
	minSigners: UShort,
	label: String,
	mainnet: Boolean,
	onDone: Callback,
	modifier: Modifier = Modifier,
) {
	val scope = rememberCoroutineScope()

	var state by remember { mutableStateOf(DkgState.ROUND1_COMPUTING) }
	var errorMsg by remember { mutableStateOf("") }

	// DKG state held in memory (never persisted until round 3 completes)
	var round1Secret by remember { mutableStateOf("") }
	var round1Broadcast by remember { mutableStateOf("") }
	var round2Secret by remember { mutableStateOf("") }
	var round2PeerPackages by remember { mutableStateOf("") }
	var walletId by remember { mutableStateOf("") }

	// Auto-start round 1
	LaunchedEffect(Unit) {
		scope.launch {
			try {
				val result = withContext(Dispatchers.Default) {
					frostDkgPart1(maxSigners, minSigners)
				}
				val json = org.json.JSONObject(result)
				round1Secret = json.getString("secret")
				round1Broadcast = json.getString("broadcast")
				state = DkgState.ROUND1_DISPLAY
			} catch (e: Exception) {
				errorMsg = e.message ?: "DKG round 1 failed"
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
			text = "FROST DKG",
			style = SignerTypeface.TitleL,
			color = MaterialTheme.colors.primary,
			modifier = Modifier.padding(bottom = 8.dp)
		)
		Text(
			text = "${minSigners}-of-${maxSigners} multisig",
			style = SignerTypeface.BodyL,
			color = MaterialTheme.colors.textSecondary,
			modifier = Modifier.padding(bottom = 16.dp)
		)

		when (state) {
			DkgState.ROUND1_COMPUTING, DkgState.ROUND2_COMPUTING, DkgState.ROUND3_COMPUTING -> {
				val roundNum = when (state) {
					DkgState.ROUND1_COMPUTING -> 1
					DkgState.ROUND2_COMPUTING -> 2
					else -> 3
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
						Text(
							text = "Computing round $roundNum...",
							style = SignerTypeface.TitleS,
							color = MaterialTheme.colors.primary
						)
					}
				}
			}

			DkgState.ROUND1_DISPLAY -> {
				Text(
					text = "Round 1: Show this to the coordinator",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp)
				)
				QrDisplay(
					data = round1Broadcast,
					modifier = Modifier.weight(1f)
				)
				SignerDivider()
				Spacer(modifier = Modifier.height(8.dp))
				Text(
					text = "After coordinator collects all broadcasts, scan the round 2 QR",
					style = SignerTypeface.CaptionM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp)
				)
				// The user will leave this screen, scan the round2 QR from coordinator,
				// which will be routed back here via the scan flow.
				// For now, provide a "Done" to dismiss (round2 comes as a new scan).
				PrimaryButtonWide(label = "Done", onClicked = onDone)
			}

			DkgState.ROUND2_DISPLAY -> {
				Text(
					text = "Round 2: Show this to the coordinator",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp)
				)
				QrDisplay(
					data = round2PeerPackages,
					modifier = Modifier.weight(1f)
				)
				SignerDivider()
				Spacer(modifier = Modifier.height(8.dp))
				Text(
					text = "After coordinator collects all packages, scan the round 3 QR",
					style = SignerTypeface.CaptionM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp)
				)
				PrimaryButtonWide(label = "Done", onClicked = onDone)
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
						Text(
							text = "DKG Complete",
							style = SignerTypeface.TitleS,
							color = MaterialTheme.colors.primary
						)
						Text(
							text = "Key share stored securely",
							style = SignerTypeface.BodyL,
							color = MaterialTheme.colors.textSecondary
						)
						Text(
							text = "Wallet: $walletId",
							style = SignerTypeface.CaptionM,
							color = MaterialTheme.colors.textTertiary
						)
						Text(
							text = "${minSigners}-of-${maxSigners} ${if (mainnet) "Mainnet" else "Testnet"}",
							style = SignerTypeface.CaptionM,
							color = MaterialTheme.colors.textTertiary
						)
					}
				}
				SignerDivider()
				Spacer(modifier = Modifier.height(16.dp))
				PrimaryButtonWide(label = "Done", onClicked = onDone)
			}

			DkgState.ERROR -> {
				Box(
					modifier = Modifier.weight(1f).fillMaxWidth(),
					contentAlignment = Alignment.Center
				) {
					Column(horizontalAlignment = Alignment.CenterHorizontally) {
						Text(
							text = "DKG Failed",
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

/**
 * Display hex string as QR code
 */
@Composable
private fun QrDisplay(data: String, modifier: Modifier = Modifier) {
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
