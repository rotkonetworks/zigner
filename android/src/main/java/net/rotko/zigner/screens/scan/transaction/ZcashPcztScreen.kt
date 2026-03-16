package net.rotko.zigner.screens.scan.transaction

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.CircularProgressIndicator
import androidx.compose.material.Icon
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
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
import io.parity.signer.uniffi.ZcashPcztInspection
import io.parity.signer.uniffi.decodeUrZcashPczt
import io.parity.signer.uniffi.inspectZcashPczt
import io.parity.signer.uniffi.signZcashPcztUr
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * PCZT signing screen with full transaction inspection.
 *
 * Shows spend/output breakdown, anchor match, known spend verification
 * before the user can approve signing.
 */

enum class PcztState {
	INSPECTING,
	REVIEW,
	SEED_SELECTION,
	SIGNING,
	DISPLAY_SIGNATURE,
	ERROR,
}

@Composable
fun ZcashPcztScreen(
	urParts: List<String>,
	onDone: Callback,
	modifier: Modifier = Modifier,
) {
	val scope = rememberCoroutineScope()

	var state by remember { mutableStateOf(PcztState.INSPECTING) }
	var errorMsg by remember { mutableStateOf("") }
	var inspection by remember { mutableStateOf<ZcashPcztInspection?>(null) }
	var pcztBytes by remember { mutableStateOf<List<UByte>>(emptyList()) }
	var signedUrParts by remember { mutableStateOf<List<String>>(emptyList()) }

	// Auto-inspect on load
	LaunchedEffect(Unit) {
		scope.launch {
			try {
				val bytes = withContext(Dispatchers.Default) {
					decodeUrZcashPczt(urParts)
				}
				pcztBytes = bytes
				val result = withContext(Dispatchers.Default) {
					inspectZcashPczt(bytes)
				}
				inspection = result
				state = PcztState.REVIEW
			} catch (e: Exception) {
				errorMsg = e.message ?: "Failed to inspect PCZT"
				state = PcztState.ERROR
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
			text = "Zcash Transaction (PCZT)",
			style = SignerTypeface.TitleL,
			color = MaterialTheme.colors.primary,
			modifier = Modifier.padding(bottom = 16.dp)
		)

		when (state) {
			PcztState.INSPECTING -> {
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
						Text("Inspecting transaction...", style = SignerTypeface.TitleS, color = MaterialTheme.colors.primary)
					}
				}
			}

			PcztState.REVIEW -> {
				val insp = inspection ?: return@Column
				Column(
					modifier = Modifier
						.weight(1f)
						.verticalScroll(rememberScrollState()),
					verticalArrangement = Arrangement.spacedBy(12.dp)
				) {
					// Anchor verification
					AnchorCard(insp)

					// Spends
					if (insp.spends.isNotEmpty()) {
						SectionCard(title = "Spending") {
							insp.spends.forEachIndexed { i, spend ->
								val zec = spend.value.toLong() / 100_000_000.0
								Row(
									modifier = Modifier.fillMaxWidth(),
									horizontalArrangement = Arrangement.SpaceBetween
								) {
									Text(
										text = if (spend.value > 0u) "%.8f ZEC".format(zec) else "redacted",
										style = SignerTypeface.BodyL,
										color = MaterialTheme.colors.primary
									)
									Text(
										text = if (spend.known) "verified" else "UNKNOWN",
										style = SignerTypeface.LabelM,
										color = if (spend.known) MaterialTheme.colors.primary else MaterialTheme.colors.red500
									)
								}
							}
						}
					}

					// Outputs
					if (insp.outputs.isNotEmpty()) {
						SectionCard(title = "Outputs") {
							insp.outputs.forEach { output ->
								val zec = output.value.toLong() / 100_000_000.0
								Column {
									Text(
										text = "%.8f ZEC".format(zec),
										style = SignerTypeface.BodyL,
										color = MaterialTheme.colors.primary
									)
									if (output.recipientHex.isNotEmpty()) {
										Text(
											text = output.recipientHex.take(16) + "...",
											style = SignerTypeface.CaptionM,
											color = MaterialTheme.colors.textTertiary
										)
									}
								}
							}
						}
					}

					// Fee
					SectionCard(title = "Fee") {
						val feeZec = insp.netValue.toLong() / 100_000_000.0
						Text(
							text = "%.8f ZEC".format(feeZec),
							style = SignerTypeface.BodyL,
							color = MaterialTheme.colors.primary
						)
					}

					// Warnings
					if (!insp.anchorMatches) {
						WarningCard("Anchor does not match verified state. Transaction may reference a different chain state.")
					}
					if (insp.knownSpends < insp.actionCount) {
						WarningCard("${insp.actionCount - insp.knownSpends} spend(s) not in verified notes. These may be unknown or dummy actions.")
					}
					if (insp.verifiedBalance == 0uL) {
						WarningCard("No verified balance. Sync notes first (zcli export-notes).")
					}
				}

				SignerDivider()
				Spacer(modifier = Modifier.height(8.dp))
				Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
					PrimaryButtonWide(
						label = "Approve & Sign",
						onClicked = {
							state = PcztState.SEED_SELECTION
							// TODO: proper seed selection; for now use first seed
							// This will be wired when integrating with ScanViewModel
						}
					)
					SecondaryButtonWide(
						label = "Decline",
						onClicked = onDone
					)
				}
			}

			PcztState.SIGNING -> {
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
						Text("Signing...", style = SignerTypeface.TitleS, color = MaterialTheme.colors.primary)
					}
				}
			}

			PcztState.DISPLAY_SIGNATURE -> {
				Text(
					text = "Signed. Show this to the coordinator.",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp)
				)
				// Display signed PCZT UR parts as animated QR
				// TODO: implement animated QR for UR parts
				Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
					Text(
						text = "${signedUrParts.size} UR part(s) ready",
						style = SignerTypeface.BodyL,
						color = MaterialTheme.colors.primary
					)
				}
				SignerDivider()
				Spacer(modifier = Modifier.height(16.dp))
				PrimaryButtonWide(label = "Done", onClicked = onDone)
			}

			PcztState.SEED_SELECTION, PcztState.ERROR -> {
				Box(
					modifier = Modifier.weight(1f).fillMaxWidth(),
					contentAlignment = Alignment.Center
				) {
					Column(horizontalAlignment = Alignment.CenterHorizontally) {
						Text(
							text = if (state == PcztState.ERROR) "Error" else "Signing",
							style = SignerTypeface.TitleS,
							color = if (state == PcztState.ERROR) MaterialTheme.colors.red500 else MaterialTheme.colors.primary
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
private fun AnchorCard(insp: ZcashPcztInspection) {
	Column(
		modifier = Modifier
			.fillMaxWidth()
			.clip(RoundedCornerShape(12.dp))
			.background(MaterialTheme.colors.fill6)
			.padding(16.dp),
		verticalArrangement = Arrangement.spacedBy(4.dp)
	) {
		Row(
			modifier = Modifier.fillMaxWidth(),
			horizontalArrangement = Arrangement.SpaceBetween
		) {
			Text("Anchor", style = SignerTypeface.LabelM, color = MaterialTheme.colors.textTertiary)
			Text(
				text = if (insp.anchorMatches) "matches" else "MISMATCH",
				style = SignerTypeface.LabelM,
				color = if (insp.anchorMatches) MaterialTheme.colors.primary else MaterialTheme.colors.red500
			)
		}
		Text(
			text = "${insp.knownSpends}/${insp.actionCount} spends verified",
			style = SignerTypeface.CaptionM,
			color = if (insp.knownSpends == insp.actionCount) MaterialTheme.colors.textSecondary else MaterialTheme.colors.red500
		)
		val balZec = insp.verifiedBalance.toLong() / 100_000_000.0
		Text(
			text = "Verified balance: ${"%.8f".format(balZec)} ZEC",
			style = SignerTypeface.CaptionM,
			color = MaterialTheme.colors.textSecondary
		)
	}
}

@Composable
private fun SectionCard(title: String, content: @Composable ColumnScope.() -> Unit) {
	Column(
		modifier = Modifier
			.fillMaxWidth()
			.clip(RoundedCornerShape(12.dp))
			.background(MaterialTheme.colors.fill6)
			.padding(16.dp),
		verticalArrangement = Arrangement.spacedBy(8.dp)
	) {
		Text(text = title, style = SignerTypeface.LabelM, color = MaterialTheme.colors.textTertiary)
		content()
	}
}

@Composable
private fun WarningCard(message: String) {
	Row(
		modifier = Modifier
			.fillMaxWidth()
			.clip(RoundedCornerShape(12.dp))
			.background(MaterialTheme.colors.red500fill12)
			.padding(12.dp),
		horizontalArrangement = Arrangement.spacedBy(8.dp),
		verticalAlignment = Alignment.Top,
	) {
		Icon(
			imageVector = Icons.Outlined.Info,
			contentDescription = null,
			tint = MaterialTheme.colors.red500,
			modifier = Modifier.size(20.dp)
		)
		Text(
			text = message,
			style = SignerTypeface.CaptionM,
			color = MaterialTheme.colors.primary
		)
	}
}
