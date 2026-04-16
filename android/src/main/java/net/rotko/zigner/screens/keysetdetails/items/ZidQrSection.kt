package net.rotko.zigner.screens.keysetdetails.items

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import net.rotko.zigner.screens.keysetdetails.export.ZidExportService
import net.rotko.zigner.ui.theme.SignerTypeface
import net.rotko.zigner.ui.theme.textSecondary
import net.rotko.zigner.ui.theme.textTertiary

/**
 * Shows a "ZID Identity" QR code section on the key set details page.
 *
 * When tapped, requests the seed phrase via getSeedPhrase callback
 * (triggers biometric auth), derives the ZID cross-site pubkey, and
 * displays it as a "zid:<hex>" QR code. Zafu scans this on the
 * identity page to associate ZID with a zigner (watch-only) wallet.
 *
 * The QR is hidden by default - user must tap and authenticate to reveal.
 */
@Composable
fun ZidQrSection(
	seedName: String,
	getSeedPhrase: suspend (String) -> String?,
	modifier: Modifier = Modifier,
) {
	var qrBitmap by remember { mutableStateOf<ImageBitmap?>(null) }
	var zidAddress by remember { mutableStateOf<String?>(null) }
	var loading by remember { mutableStateOf(false) }
	var expanded by remember { mutableStateOf(false) }
	val scope = rememberCoroutineScope()

	val plateShape = RoundedCornerShape(12.dp)

	Column(
		modifier = modifier
			.fillMaxWidth()
			.padding(horizontal = 24.dp),
		horizontalAlignment = Alignment.CenterHorizontally,
	) {
		Text(
			text = if (expanded) "zid identity" else "show zid identity QR",
			color = MaterialTheme.colors.textSecondary,
			style = SignerTypeface.BodyM,
			textAlign = TextAlign.Center,
			modifier = Modifier
				.clickable {
					if (!expanded && !loading) {
						loading = true
						scope.launch {
							val phrase = getSeedPhrase(seedName)
							if (phrase != null) {
								val service = ZidExportService()
								qrBitmap = service.getZidQr(phrase)
								zidAddress = service.getZidPubkey(phrase)?.let { "zid${it.take(16)}" }
								expanded = true
							}
							loading = false
						}
					} else {
						expanded = false
						qrBitmap = null
						zidAddress = null
					}
				}
				.padding(vertical = 8.dp)
		)

		if (loading && !expanded) {
			Text(
				text = "authenticating...",
				color = MaterialTheme.colors.textTertiary,
				style = SignerTypeface.BodyS,
				modifier = Modifier.padding(vertical = 16.dp)
			)
		}

		if (expanded) {
			qrBitmap?.let { bitmap ->
				Box(
					modifier = Modifier
						.fillMaxWidth()
						.aspectRatio(1f)
						.clip(plateShape)
						.background(Color.White, plateShape),
					contentAlignment = Alignment.Center,
				) {
					Image(
						bitmap = bitmap,
						contentDescription = "ZID identity QR",
						contentScale = ContentScale.Fit,
						modifier = Modifier.padding(8.dp)
					)
				}

				zidAddress?.let { addr ->
					Text(
						text = addr,
						color = MaterialTheme.colors.textSecondary,
						style = SignerTypeface.BodyM,
						textAlign = TextAlign.Center,
						modifier = Modifier.padding(top = 8.dp)
					)
				}

				Text(
					text = "scan with zafu to import identity",
					color = MaterialTheme.colors.textTertiary,
					style = SignerTypeface.BodyS,
					textAlign = TextAlign.Center,
					modifier = Modifier.padding(top = 4.dp, bottom = 4.dp)
				)
			}
		}
	}
}
