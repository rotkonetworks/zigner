package net.rotko.zigner.screens.scan.transaction

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.CircularProgressIndicator
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.components.qrcode.AnimatedQrKeysInfo
import net.rotko.zigner.components.qrcode.EmptyQrCodeProvider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*
import io.parity.signer.uniffi.signZidQr
import io.parity.signer.uniffi.encodeToQr
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * ZID identity sign screen — scan {"type":"zid-sign",...} QR from zafu,
 * review the request details, sign with the ZID key, display response QR.
 */

enum class ZidSignState {
	REVIEW,
	SIGNING,
	DISPLAY_RESPONSE,
	ERROR,
}

@Composable
fun ZidSignScreen(
	qrJson: JSONObject,
	seedPhrase: String,
	onDone: Callback,
	modifier: Modifier = Modifier,
) {
	val scope = rememberCoroutineScope()
	var state by remember { mutableStateOf(ZidSignState.REVIEW) }
	var errorMsg by remember { mutableStateOf("") }
	var responseJson by remember { mutableStateOf("") }

	val origin = qrJson.optString("origin", "unknown")
	val identity = qrJson.optString("identity", "default")
	val mode = qrJson.optString("mode", "site")
	val rotation = qrJson.optInt("rotation", 0)
	val algorithm = qrJson.optString("algorithm", "ed25519")
	val statement = qrJson.optString("statement", "")
	val challengeHex = qrJson.optString("challenge", "")

	Column(
		modifier = modifier
			.fillMaxSize()
			.background(MaterialTheme.colors.background)
			.padding(16.dp)
	) {
		Text(
			text = "ZID Identity Sign",
			style = SignerTypeface.TitleL,
			color = MaterialTheme.colors.primary,
			modifier = Modifier.padding(bottom = 16.dp)
		)

		when (state) {
			ZidSignState.REVIEW -> {
				Column(
					modifier = Modifier.weight(1f),
					verticalArrangement = Arrangement.spacedBy(12.dp)
				) {
					// Origin — big and prominent
					Column(
						modifier = Modifier
							.fillMaxWidth()
							.clip(RoundedCornerShape(12.dp))
							.background(MaterialTheme.colors.fill6)
							.padding(24.dp),
						horizontalAlignment = Alignment.CenterHorizontally,
						verticalArrangement = Arrangement.spacedBy(8.dp)
					) {
						Text(
							text = "Sign identity for",
							style = SignerTypeface.LabelM,
							color = MaterialTheme.colors.textTertiary
						)
						Text(
							text = origin,
							style = SignerTypeface.TitleL,
							color = MaterialTheme.colors.primary,
							textAlign = TextAlign.Center
						)
					}

					// Statement
					if (statement.isNotEmpty()) {
						Column(
							modifier = Modifier
								.fillMaxWidth()
								.clip(RoundedCornerShape(8.dp))
								.background(MaterialTheme.colors.fill6)
								.padding(12.dp),
						) {
							Text(
								text = statement,
								style = SignerTypeface.BodyM,
								color = MaterialTheme.colors.textSecondary
							)
						}
					}

					// Details
					Column(
						modifier = Modifier
							.fillMaxWidth()
							.clip(RoundedCornerShape(8.dp))
							.background(MaterialTheme.colors.fill6)
							.padding(12.dp),
						verticalArrangement = Arrangement.spacedBy(6.dp)
					) {
						DetailRow("identity", identity)
						DetailRow("mode", if (mode == "cross-site") "cross-site (linkable)" else "site-specific")
						if (mode == "site" && rotation > 0) {
							DetailRow("rotation", "#$rotation")
						}
						DetailRow("algorithm", algorithm)
						DetailRow("challenge", if (challengeHex.length > 32) challengeHex.take(32) + "..." else challengeHex)
					}

					// Safety note
					Text(
						text = "This will sign a challenge proving your identity. No transactions or funds are involved.",
						style = SignerTypeface.CaptionM,
						color = MaterialTheme.colors.textTertiary,
						modifier = Modifier.padding(top = 4.dp)
					)
				}

				SignerDivider()
				Spacer(modifier = Modifier.height(8.dp))
				Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
					PrimaryButtonWide(
						label = "Approve",
						onClicked = {
							state = ZidSignState.SIGNING
							scope.launch {
								try {
									responseJson = withContext(Dispatchers.Default) {
										signZidQr(seedPhrase, qrJson.toString())
									}
									state = ZidSignState.DISPLAY_RESPONSE
								} catch (e: Exception) {
									errorMsg = e.message ?: "Signing failed"
									state = ZidSignState.ERROR
								}
							}
						}
					)
					SecondaryButtonWide(label = "Decline", onClicked = onDone)
				}
			}

			ZidSignState.SIGNING -> {
				Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
					Column(horizontalAlignment = Alignment.CenterHorizontally) {
						CircularProgressIndicator(color = MaterialTheme.colors.pink500, modifier = Modifier.size(48.dp))
						Spacer(modifier = Modifier.height(16.dp))
						Text("Signing...", style = SignerTypeface.TitleS, color = MaterialTheme.colors.primary)
					}
				}
			}

			ZidSignState.DISPLAY_RESPONSE -> {
				Text(
					text = "Show this to zafu",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier.padding(bottom = 8.dp)
				)
				val qrBytes = remember(responseJson) {
					try {
						val bytes = responseJson.toByteArray(Charsets.UTF_8).map { it.toUByte() }
						kotlinx.coroutines.runBlocking { encodeToQr(bytes, false) }
					} catch (_: Exception) { null }
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
				Spacer(modifier = Modifier.height(16.dp))
				PrimaryButtonWide(label = "Done", onClicked = onDone)
			}

			ZidSignState.ERROR -> {
				Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
					Column(horizontalAlignment = Alignment.CenterHorizontally) {
						Text("Error", style = SignerTypeface.TitleS, color = MaterialTheme.colors.red500)
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

@Composable
private fun DetailRow(label: String, value: String) {
	Row(
		modifier = Modifier.fillMaxWidth(),
		horizontalArrangement = Arrangement.SpaceBetween
	) {
		Text(
			text = label,
			style = SignerTypeface.CaptionM,
			color = MaterialTheme.colors.textTertiary
		)
		Text(
			text = value,
			style = SignerTypeface.CaptionM,
			color = MaterialTheme.colors.textSecondary
		)
	}
}
