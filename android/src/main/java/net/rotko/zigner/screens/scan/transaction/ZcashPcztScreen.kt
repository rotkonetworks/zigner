package net.rotko.zigner.screens.scan.transaction

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.CircularProgressIndicator
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Tab
import androidx.compose.material.TabRow
import androidx.compose.material.TabRowDefaults
import androidx.compose.material.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*
import io.parity.signer.uniffi.ZcashPcztInspection
import io.parity.signer.uniffi.decodeUrZcashPczt
import io.parity.signer.uniffi.encodeToQr
import io.parity.signer.uniffi.inspectZcashPczt
import io.parity.signer.uniffi.signZcashPcztUr
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.time.Duration.Companion.milliseconds

// Inspect → review (Basic/Advanced tabs) → sign → render signed UR back as
// animated QR for the coordinator (zafu) to scan and broadcast.

enum class PcztState {
	INSPECTING,
	WARN_UNRECOGNIZED,
	REVIEW,
	SIGNING,
	DISPLAY_SIGNATURE,
	ERROR,
}

/** Soft safety signal (rotkonetworks/zigner#16; the Keystone-parity design of
 *  6e5ca104): none of the PCZT's spends match a note this device has verified.
 *  Only meaningful once notes have been synced (verifiedBalance > 0) — a
 *  never-synced device falls back to plain Keystone-shape review. Fires on a
 *  forged / unrecognized PCZT, and also when spending only stale change after a
 *  prior send (its nullifier isn't synced yet) — which is why it's a soft
 *  acknowledge, not a hard refuse. */
private fun noRecognizedSpends(insp: ZcashPcztInspection): Boolean =
	insp.verifiedBalance > 0uL && insp.knownSpends == 0u && insp.actionCount > 0u

@Composable
fun ZcashPcztScreen(
	urParts: List<String>,
	getSeedPhrase: suspend () -> String,
	getSeedName: suspend () -> String,
	onDone: Callback,
	modifier: Modifier = Modifier,
) {
	val scope = rememberCoroutineScope()

	var state by remember { mutableStateOf(PcztState.INSPECTING) }
	var errorMsg by remember { mutableStateOf("") }
	var inspection by remember { mutableStateOf<ZcashPcztInspection?>(null) }
	var selectedTab by remember { mutableStateOf(0) }
	var signedQrFrames by remember { mutableStateOf<List<ImageBitmap>>(emptyList()) }
	var currentFrameIdx by remember { mutableStateOf(0) }
	// Captured at inspect time so the on-screen identity matches the seed
	// that will sign (vs. re-fetching at click time and risking a different
	// map-iteration first value if seeds change between review and sign).
	var signingSeedName by remember { mutableStateOf("") }
	val accountIndex: UInt = 0u

	LaunchedEffect(Unit) {
		scope.launch {
			try {
				val bytes = withContext(Dispatchers.Default) { decodeUrZcashPczt(urParts) }
				val result = withContext(Dispatchers.Default) { inspectZcashPczt(bytes) }
				inspection = result
				signingSeedName = getSeedName()
				// Gate review behind an acknowledge page when none of the spends
				// are recognized on this device (soft warning, rotkonetworks/zigner#16).
				state = if (noRecognizedSpends(result)) PcztState.WARN_UNRECOGNIZED else PcztState.REVIEW
			} catch (e: Exception) {
				errorMsg = e.message ?: "Failed to inspect PCZT"
				state = PcztState.ERROR
			}
		}
	}

	// 1.4 fps cycle — webcams without macro need ~600-800ms to autofocus on a
	// changing subject. Faster than this and focus hunts indefinitely on the
	// rapidly-changing pattern, so the camera reads zero successful QRs.
	LaunchedEffect(signedQrFrames) {
		if (signedQrFrames.isEmpty()) return@LaunchedEffect
		var idx = 0
		while (true) {
			currentFrameIdx = idx
			delay(700.milliseconds)
			idx = (idx + 1) % signedQrFrames.size
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
			PcztState.INSPECTING -> CenteredSpinner("Inspecting transaction...")

			PcztState.WARN_UNRECOGNIZED -> {
				UnrecognizedSpendsPage(
					onProceed = { state = PcztState.REVIEW },
					onCancel = onDone,
				)
			}

			PcztState.REVIEW -> {
				val insp = inspection ?: return@Column
				val signRequest = SignRequest.ZcashPczt(urParts = urParts, inspection = insp)

				// Identity header — make explicit which seed + account is
				// about to sign. Account index is currently hardcoded; this
				// row at least surfaces "what you're authorizing with."
				Text(
					text = "Signing as: ${signingSeedName.ifEmpty { "(no seed available)" }} · account $accountIndex",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp),
				)

				val tabs = listOf("Basic", "Advanced")
				TabRow(
					selectedTabIndex = selectedTab,
					backgroundColor = MaterialTheme.colors.background,
					contentColor = MaterialTheme.colors.primary,
					indicator = { positions ->
						TabRowDefaults.Indicator(
							modifier = Modifier.tabIndicatorOffset(positions[selectedTab]),
							color = MaterialTheme.colors.primary,
						)
					},
				) {
					tabs.forEachIndexed { i, title ->
						Tab(
							selected = selectedTab == i,
							onClick = { selectedTab = i },
							text = {
								Text(
									text = title,
									style = SignerTypeface.LabelM,
									color = if (selectedTab == i) MaterialTheme.colors.primary
									else MaterialTheme.colors.textTertiary,
								)
							},
						)
					}
				}

				Column(
					modifier = Modifier
						.weight(1f)
						.verticalScroll(rememberScrollState())
						.padding(top = 12.dp),
					verticalArrangement = Arrangement.spacedBy(12.dp),
				) {
					// Verified-notes context — shown only when this device has
					// synced notes; a never-synced device stays Keystone-shape (no
					// noise). The hard refuse is intentionally not re-enabled; the
					// no-recognized-spends case surfaces as the WARN_UNRECOGNIZED
					// acknowledge page before this screen.
					if (insp.verifiedBalance > 0uL) {
						VerificationCard(insp)
					}
					when (selectedTab) {
						0 -> {
							ZcashPcztSimpleContent(signRequest)
							// Soft signal: some spends aren't recognized (may be
							// dummies or notes not synced to this device).
							if (insp.verifiedBalance > 0uL && insp.knownSpends < insp.actionCount) {
								WarningCard("${insp.actionCount - insp.knownSpends} spend(s) not in verified notes. These may be unknown or dummy actions.")
							}
							if (insp.verifiedBalance > 0uL) {
								PcztGlossaryNote(insp)
							}
						}
						1 -> PcztAdvancedContent(insp, urParts)
					}
				}

				SignerDivider()
				Spacer(modifier = Modifier.height(8.dp))
				Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
					PrimaryButtonWide(
						label = "Approve & Sign",
						onClicked = {
							state = PcztState.SIGNING
							scope.launch {
								try {
									val seedPhrase = getSeedPhrase()
									if (seedPhrase.isEmpty()) {
										errorMsg = "No seed phrase available"
										state = PcztState.ERROR
										return@launch
									}
									val signed = withContext(Dispatchers.Default) {
										// 200-byte fragments give ~v15-20 QRs (webcam-friendly).
										// Bumping past 300 makes desktop webcams fail to lock.
										signZcashPcztUr(seedPhrase, accountIndex, urParts, 200u)
									}
									// Pre-render so the ticker just swaps bitmaps without
									// per-frame compute, keeping the animation smooth.
									val bitmaps = withContext(Dispatchers.Default) {
										signed.map { urString ->
											val bytes = urString.toByteArray(Charsets.UTF_8).map { it.toUByte() }
											val pngBytes = encodeToQr(bytes, false)
											val byteArray = pngBytes.map { it.toByte() }.toByteArray()
											BitmapFactory.decodeByteArray(byteArray, 0, byteArray.size).asImageBitmap()
										}
									}
									signedQrFrames = bitmaps
									state = PcztState.DISPLAY_SIGNATURE
								} catch (e: Exception) {
									errorMsg = e.message ?: "Signing failed"
									state = PcztState.ERROR
								}
							}
						},
					)
					SecondaryButtonWide(label = "Decline", onClicked = onDone)
				}
			}

			PcztState.SIGNING -> CenteredSpinner("Signing...")

			PcztState.DISPLAY_SIGNATURE -> {
				Text(
					text = "Show this QR to your wallet (zafu / zodl / vizor)",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp),
				)
				Box(
					modifier = Modifier.weight(1f).fillMaxWidth(),
					contentAlignment = Alignment.Center,
				) {
					signedQrFrames.getOrNull(currentFrameIdx)?.let { bitmap ->
						Box(
							modifier = Modifier
								.fillMaxWidth()
								.aspectRatio(1f)
								.clip(RoundedCornerShape(12.dp))
								.background(Color.White),
							contentAlignment = Alignment.Center,
						) {
							Image(
								bitmap = bitmap,
								contentDescription = "Signed PCZT QR frame",
								contentScale = ContentScale.Fit,
								modifier = Modifier.fillMaxSize(),
							)
						}
					}
				}
				Text(
					text = if (signedQrFrames.size > 1)
						"frame ${currentFrameIdx + 1} / ${signedQrFrames.size}"
					else
						"single frame",
					style = SignerTypeface.CaptionM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(top = 8.dp).align(Alignment.CenterHorizontally),
				)
				SignerDivider()
				Spacer(modifier = Modifier.height(16.dp))
				PrimaryButtonWide(label = "Done", onClicked = onDone)
			}

			PcztState.ERROR -> {
				Box(
					modifier = Modifier.weight(1f).fillMaxWidth(),
					contentAlignment = Alignment.Center,
				) {
					Column(horizontalAlignment = Alignment.CenterHorizontally) {
						Text(
							text = "Error",
							style = SignerTypeface.TitleS,
							color = MaterialTheme.colors.red500,
						)
						Spacer(modifier = Modifier.height(8.dp))
						Text(
							text = errorMsg,
							style = SignerTypeface.BodyL,
							color = MaterialTheme.colors.textSecondary,
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
private fun ColumnScope.CenteredSpinner(label: String) {
	Box(
		modifier = Modifier.weight(1f).fillMaxWidth(),
		contentAlignment = Alignment.Center,
	) {
		Column(horizontalAlignment = Alignment.CenterHorizontally) {
			CircularProgressIndicator(
				color = MaterialTheme.colors.pink500,
				modifier = Modifier.size(48.dp),
			)
			Spacer(modifier = Modifier.height(16.dp))
			Text(label, style = SignerTypeface.TitleS, color = MaterialTheme.colors.primary)
		}
	}
}

@Composable
private fun VerificationCard(insp: ZcashPcztInspection) {
	Column(
		modifier = Modifier
			.fillMaxWidth()
			.clip(RoundedCornerShape(12.dp))
			.background(MaterialTheme.colors.fill6)
			.padding(16.dp),
		verticalArrangement = Arrangement.spacedBy(4.dp),
	) {
		Text(
			text = "${insp.knownSpends}/${insp.actionCount} spends verified",
			style = SignerTypeface.CaptionM,
			color = if (insp.knownSpends == insp.actionCount) MaterialTheme.colors.textSecondary else MaterialTheme.colors.red500,
		)
		val balZec = insp.verifiedBalance.toLong() / 100_000_000.0
		Text(
			text = "Verified balance: ${"%.8f".format(balZec)} ZEC",
			style = SignerTypeface.CaptionM,
			color = MaterialTheme.colors.textSecondary,
		)
	}
}

// Plain-language note explaining orchard semantics surfaces in this screen.
@Composable
private fun PcztGlossaryNote(insp: ZcashPcztInspection) {
	val outputCount = insp.outputs.size
	val msg = buildString {
		appendLine("• ${insp.actionCount} action(s) = ${insp.actionCount} spend(s) + $outputCount output(s) (Orchard bundles them).")
		if (outputCount >= 2) {
			appendLine("• Outputs include both your destination AND change back to your wallet (different diversifier of your UFVK).")
		}
		append("• Spends marked UNKNOWN are either dummies (privacy padding) or real notes you haven't synced to this device yet.")
	}
	Text(
		text = msg,
		style = SignerTypeface.CaptionM,
		color = MaterialTheme.colors.textTertiary,
		modifier = Modifier
			.fillMaxWidth()
			.clip(RoundedCornerShape(8.dp))
			.background(MaterialTheme.colors.fill6)
			.padding(12.dp),
	)
}

// Soft-warning interstitial: none of the tx's spends are recognized on this
// device. Non-blocking — the user can acknowledge and proceed (rotkonetworks/zigner#16).
@Composable
private fun UnrecognizedSpendsPage(
	onProceed: Callback,
	onCancel: Callback,
) {
	Column(
		modifier = Modifier.fillMaxSize(),
		verticalArrangement = Arrangement.SpaceBetween,
	) {
		Column(
			modifier = Modifier
				.weight(1f)
				.verticalScroll(rememberScrollState())
				.padding(top = 12.dp),
			verticalArrangement = Arrangement.spacedBy(12.dp),
		) {
			Text(
				text = "\u26A0 Unrecognized spends",
				style = SignerTypeface.TitleS,
				color = MaterialTheme.colors.red500,
			)
			Text(
				text = "None of this transaction's spends match notes verified on this device.",
				style = SignerTypeface.BodyL,
				color = MaterialTheme.colors.textSecondary,
			)
			Text(
				text = "If you have sent funds since your last sync, this can be expected — the change from earlier sends is not verified on this device yet. Otherwise, this transaction may spend notes you do not recognize. Re-sync your notes from zafu and verify the recipient and amount carefully before proceeding.",
				style = SignerTypeface.CaptionM,
				color = MaterialTheme.colors.textTertiary,
				modifier = Modifier
					.fillMaxWidth()
					.clip(RoundedCornerShape(8.dp))
					.background(MaterialTheme.colors.fill6)
					.padding(12.dp),
			)
		}
		SignerDivider()
		Spacer(modifier = Modifier.height(8.dp))
		Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
			PrimaryButtonWide(label = "Acknowledge and proceed", onClicked = onProceed)
			SecondaryButtonWide(label = "Cancel", onClicked = onCancel)
		}
	}
}

// Advanced tab — raw PCZT internals for cross-checking against the coordinator.
@Composable
private fun PcztAdvancedContent(insp: ZcashPcztInspection, urParts: List<String>) {
	DetailRow(label = "Actions", value = "${insp.actionCount}")
	DetailRow(label = "Tx version", value = "v${insp.txVersion}")
	DetailRow(label = "Branch ID", value = "0x${insp.consensusBranchIdHex}")
	DetailRow(label = "Expiry height", value = "${insp.expiryHeight}")
	DetailRow(label = "UR parts", value = "${urParts.size}")

	if (insp.spends.isNotEmpty()) {
		Text(
			text = "Spend nullifiers",
			style = SignerTypeface.LabelM,
			color = MaterialTheme.colors.textTertiary,
			modifier = Modifier.padding(top = 4.dp),
		)
		insp.spends.forEachIndexed { i, sp ->
			Text(
				text = "[$i] ${sp.nullifierHex}${if (sp.known) "  ✓" else ""}",
				style = SignerTypeface.CaptionM.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp),
				color = if (sp.known) MaterialTheme.colors.textSecondary else MaterialTheme.colors.red500,
				modifier = Modifier
					.fillMaxWidth()
					.clip(RoundedCornerShape(6.dp))
					.background(MaterialTheme.colors.fill6)
					.padding(8.dp),
			)
		}
	}

	if (insp.outputs.isNotEmpty()) {
		Text(
			text = "Output recipients",
			style = SignerTypeface.LabelM,
			color = MaterialTheme.colors.textTertiary,
			modifier = Modifier.padding(top = 4.dp),
		)
		insp.outputs.forEachIndexed { i, out ->
			val zec = "%.8f".format(out.value.toLong() / 100_000_000.0)
			Text(
				text = "[$i] $zec ZEC\n${out.recipient}",
				style = SignerTypeface.CaptionM.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp),
				color = MaterialTheme.colors.textSecondary,
				modifier = Modifier
					.fillMaxWidth()
					.clip(RoundedCornerShape(6.dp))
					.background(MaterialTheme.colors.fill6)
					.padding(8.dp),
			)
		}
	}
}
