package net.rotko.zigner.screens.scan.transaction

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.parity.signer.uniffi.encodeToQr
import io.parity.signer.uniffi.releaseSigningPubkey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.qrcode.AnimatedQrKeysInfo
import net.rotko.zigner.components.qrcode.EmptyQrCodeProvider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*

// Step zero of the key ceremony: show this device's release public key so it
// can be baked into RELEASE_KEY_BYTES.
//
// Nothing secret leaves here - a public key is public. What matters is that
// the three keys come from three DIFFERENT seeds on three different devices.
// 2-of-3 only buys anything if the keys can fail independently; three keys
// derived from one seed, or three devices sitting in one drawer, is 1-of-1
// wearing a costume. The screen says so, because this is the moment the
// mistake gets made and it is invisible afterwards.
//
// Read-only: no approval, no signature, nothing consumed. Safe to open twice.

@Composable
fun ReleaseKeyScreen(
	seedPhrase: String,
	onDone: Callback,
	modifier: Modifier = Modifier,
) {
	var keyIndex by remember { mutableStateOf(0u) }
	var pubkeyHex by remember { mutableStateOf("") }
	var error by remember { mutableStateOf("") }

	LaunchedEffect(keyIndex) {
		pubkeyHex = ""
		error = ""
		try {
			pubkeyHex = withContext(Dispatchers.Default) {
				releaseSigningPubkey(seedPhrase, keyIndex)
			}
		} catch (e: Exception) {
			error = e.message ?: "derivation failed"
		}
	}

	Column(
		modifier = modifier
			.fillMaxSize()
			.verticalScroll(rememberScrollState())
			.padding(horizontal = 24.dp)
			.padding(top = 32.dp, bottom = 24.dp),
	) {
		Text(
			text = "Release key",
			color = MaterialTheme.colors.primary,
			style = SignerTypeface.TitleL,
		)
		Spacer(Modifier.padding(top = 8.dp))
		Text(
			text = "This device's public key for signing module releases. Give it " +
				"to whoever is assembling the 2-of-3 set.",
			color = MaterialTheme.colors.textSecondary,
			style = SignerTypeface.BodyM,
		)

		Spacer(Modifier.padding(top = 24.dp))
		Text(
			text = "Key slot",
			color = MaterialTheme.colors.textTertiary,
			style = SignerTypeface.BodyM,
		)
		Spacer(Modifier.padding(top = 8.dp))
		Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
			for (i in 0u..2u) {
				val selected = keyIndex == i
				Box(
					modifier = Modifier
						.weight(1f)
						.clip(RoundedCornerShape(8.dp))
						.background(
							if (selected) MaterialTheme.colors.pink500
							else MaterialTheme.colors.fill6
						)
						.clickable { keyIndex = i }
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
		Spacer(Modifier.padding(top = 4.dp))
		Text(
			text = "Each of the three devices takes a different slot. The slot is " +
				"the position in RELEASE_KEY_BYTES, not a ranking.",
			color = MaterialTheme.colors.textTertiary,
			style = SignerTypeface.CaptionM,
		)

		Spacer(Modifier.padding(top = 24.dp))
		if (error.isNotEmpty()) {
			Text(
				text = error,
				color = MaterialTheme.colors.red500,
				style = SignerTypeface.BodyM,
			)
		} else if (pubkeyHex.isNotEmpty()) {
			Text(
				text = "Public key",
				color = MaterialTheme.colors.textTertiary,
				style = SignerTypeface.BodyM,
			)
			Spacer(Modifier.padding(top = 8.dp))
			Text(
				text = pubkeyHex.chunked(8).joinToString(" ").uppercase(),
				color = MaterialTheme.colors.primary,
				fontFamily = FontFamily.Monospace,
				fontSize = 13.sp,
				modifier = Modifier
					.fillMaxWidth()
					.clip(RoundedCornerShape(8.dp))
					.background(MaterialTheme.colors.fill6)
					.padding(16.dp),
			)

			Spacer(Modifier.padding(top = 16.dp))
			val qr = remember(pubkeyHex, keyIndex) {
				runCatching {
					// `index:hex`, the same shape as a signature, so the
					// collector parses one format rather than two.
					val payload = "$keyIndex:$pubkeyHex"
					kotlinx.coroutines.runBlocking {
						encodeToQr(payload.toByteArray(Charsets.UTF_8).map { it.toUByte() }, false)
					}
				}.getOrNull()
			}
			Box(
				modifier = Modifier.fillMaxWidth().heightIn(min = 260.dp),
				contentAlignment = Alignment.Center,
			) {
				if (qr != null) {
					AnimatedQrKeysInfo<List<List<UByte>>>(
						input = listOf(qr),
						provider = EmptyQrCodeProvider(),
						modifier = Modifier.fillMaxWidth(),
					)
				}
			}

			Spacer(Modifier.padding(top = 8.dp))
			Text(
				text = "$keyIndex:$pubkeyHex",
				color = MaterialTheme.colors.textTertiary,
				fontFamily = FontFamily.Monospace,
				fontSize = 10.sp,
				modifier = Modifier
					.fillMaxWidth()
					.clip(RoundedCornerShape(8.dp))
					.background(MaterialTheme.colors.fill6)
					.padding(12.dp),
			)

			Spacer(Modifier.padding(top = 20.dp))
			Text(
				text = "Three keys, three seeds, three devices. If two of them share " +
					"a seed or sit in the same place, the threshold protects nothing " +
					"- a single theft or a single compromise takes both.",
				color = MaterialTheme.colors.textTertiary,
				style = SignerTypeface.CaptionM,
			)
		}

		Spacer(Modifier.padding(top = 32.dp))
		PrimaryButtonWide(label = "Done", onClicked = onDone)
	}
}
