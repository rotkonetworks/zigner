package net.rotko.zigner.screens.settings.releasekey

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Key
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.launch
import net.rotko.zigner.components.base.ScreenHeaderClose
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.screens.scan.transaction.ReleaseKeyScreen
import net.rotko.zigner.screens.settings.general.SettingsElement
import net.rotko.zigner.ui.theme.SignerTypeface
import net.rotko.zigner.ui.theme.textSecondary

// Settings entry for the release-key ceremony. Pick a seed, unlock it, then
// hand off to ReleaseKeyScreen (slot picker + pubkey + QR). Mirrors the Penumbra
// FVK export flow, because "select a seed, then derive-and-show something public
// from it" is the same shape.
@Composable
fun ReleaseKeyIntegratedScreen(
	onBack: Callback,
) {
	val viewModel = viewModel<ReleaseKeyViewModel>()
	val seeds = remember { viewModel.getSeeds() }
	var seedPhrase by remember { mutableStateOf<String?>(null) }
	var loading by remember { mutableStateOf(false) }
	val scope = rememberCoroutineScope()

	Box(modifier = Modifier.statusBarsPadding()) {
		val phrase = seedPhrase
		if (phrase != null) {
			ReleaseKeyScreen(seedPhrase = phrase, onDone = onBack)
		} else {
			Column(
				modifier = Modifier
					.fillMaxSize()
					.background(MaterialTheme.colors.background),
			) {
				ScreenHeaderClose(title = "Release key", onClose = onBack)
				Text(
					text = "Pick the seed this device derives its release key from. " +
						"The key never leaves the device - only its public half, on the " +
						"next screen, does.",
					style = SignerTypeface.BodyM,
					color = MaterialTheme.colors.textSecondary,
					modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp),
				)
				if (seeds.isEmpty()) {
					Text(
						text = "No seeds on this device yet.",
						style = SignerTypeface.BodyM,
						color = MaterialTheme.colors.textSecondary,
						modifier = Modifier.padding(horizontal = 24.dp),
					)
				}
				Column(
					modifier = Modifier
						.weight(1f)
						.verticalScroll(rememberScrollState()),
					verticalArrangement = Arrangement.spacedBy(2.dp),
				) {
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
				}
				if (loading) {
					Box(
						modifier = Modifier.fillMaxWidth().padding(16.dp),
						contentAlignment = Alignment.Center,
					) {
						Text(
							text = "Unlocking…",
							style = SignerTypeface.BodyM,
							color = MaterialTheme.colors.textSecondary,
						)
					}
				}
			}
		}
	}
}
