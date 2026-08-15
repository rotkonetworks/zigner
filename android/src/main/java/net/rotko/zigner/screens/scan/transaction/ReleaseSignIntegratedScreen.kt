package net.rotko.zigner.screens.scan.transaction

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Key
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import io.parity.signer.uniffi.ReleaseSigningRequest
import io.parity.signer.uniffi.releaseClassifyRequest
import kotlinx.coroutines.launch
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.ScreenHeaderClose
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.screens.settings.general.SettingsElement
import net.rotko.zigner.screens.settings.releasekey.ReleaseKeyViewModel
import net.rotko.zigner.ui.theme.*

// Scan-flow entry for release signing. The camera has already recognised a
// base64 manifest prefix (magic "ZIGM", classified by releaseClassifyRequest);
// this wraps the existing ReleaseSignScreen with the two things a scan cannot
// carry: which slot this device is (0 is the GitHub/CI key, so a device is 1 or
// 2) and the seed to sign with (unlocked behind biometric auth). The prefix is
// re-classified here so a malformed one fails closed with a message rather than
// reaching the signer.
@Composable
fun ReleaseSignIntegratedScreen(
	prefixBytes: ByteArray,
	onDone: Callback,
) {
	val viewModel = viewModel<ReleaseKeyViewModel>()
	val seeds = remember { viewModel.getSeeds() }
	val request: ReleaseSigningRequest? = remember(prefixBytes) {
		runCatching { releaseClassifyRequest(prefixBytes.map { it.toUByte() }) }.getOrNull()
	}
	var slot by remember { mutableStateOf(1u) }
	var seedPhrase by remember { mutableStateOf<String?>(null) }
	var loading by remember { mutableStateOf(false) }
	val scope = rememberCoroutineScope()

	Box(modifier = Modifier.statusBarsPadding()) {
		val phrase = seedPhrase
		when {
			request == null -> {
				Column(
					modifier = Modifier.fillMaxSize().background(MaterialTheme.colors.background),
				) {
					ScreenHeaderClose(title = "Release", onClose = onDone)
					Text(
						text = "This QR is not an exact release prefix - refusing to sign it.",
						style = SignerTypeface.BodyM,
						color = MaterialTheme.colors.red500,
						modifier = Modifier.padding(24.dp),
					)
					Spacer(Modifier.weight(1f))
					Box(Modifier.padding(24.dp)) {
						PrimaryButtonWide(label = "Close", onClicked = onDone)
					}
				}
			}

			phrase != null -> {
				ReleaseSignScreen(
					request = request,
					prefixBytes = prefixBytes,
					seedPhrase = phrase,
					keyIndex = slot,
					onDone = onDone,
				)
			}

			else -> {
				Column(
					modifier = Modifier
						.fillMaxSize()
						.verticalScroll(rememberScrollState())
						.background(MaterialTheme.colors.background),
				) {
					ScreenHeaderClose(title = "Sign release", onClose = onDone)
					Text(
						text = "Which slot is this device? Slot 0 is the GitHub/CI key, " +
							"so a zigner is 1 or 2 - it must match how the keys were baked.",
						style = SignerTypeface.BodyM,
						color = MaterialTheme.colors.textSecondary,
						modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp),
					)
					Row(
						modifier = Modifier.padding(horizontal = 24.dp),
						horizontalArrangement = Arrangement.spacedBy(8.dp),
					) {
						for (i in 0u..2u) {
							val selected = slot == i
							Box(
								modifier = Modifier
									.weight(1f)
									.clip(RoundedCornerShape(8.dp))
									.background(
										if (selected) MaterialTheme.colors.pink500
										else MaterialTheme.colors.fill6
									)
									.clickable { slot = i }
									.padding(vertical = 12.dp),
								contentAlignment = Alignment.Center,
							) {
								Text(
									text = "#$i",
									color = if (selected) Color.White else MaterialTheme.colors.primary,
									style = SignerTypeface.BodyM,
								)
							}
						}
					}
					Spacer(Modifier.padding(top = 24.dp))
					Text(
						text = "Pick the seed for this device's release key:",
						style = SignerTypeface.BodyM,
						color = MaterialTheme.colors.textSecondary,
						modifier = Modifier.padding(horizontal = 24.dp),
					)
					Spacer(Modifier.padding(top = 8.dp))
					for (seedName in seeds) {
						SettingsElement(
							name = seedName,
							icon = Icons.Outlined.Key,
							onClick = {
								if (loading) return@SettingsElement
								loading = true
								scope.launch {
									val p = viewModel.getSeedPhrase(seedName)
									if (p != null) seedPhrase = p
									loading = false
								}
							},
						)
					}
					if (loading) {
						Text(
							text = "Unlocking…",
							style = SignerTypeface.BodyM,
							color = MaterialTheme.colors.textSecondary,
							modifier = Modifier.padding(24.dp),
						)
					}
				}
			}
		}
	}
}
