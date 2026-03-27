package net.rotko.zigner.screens.scan.transaction

import androidx.compose.foundation.background
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
import androidx.compose.ui.unit.dp
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*
import io.parity.signer.uniffi.ZcashNoteSyncResult
import java.text.NumberFormat
import java.util.Locale

/**
 * Zcash note sync result screen
 * Shows verified note count, balance, and anchor info after QR scan
 */
@Composable
fun ZcashNoteSyncScreen(
	result: ZcashNoteSyncResult,
	onDone: Callback,
	modifier: Modifier = Modifier,
) {
	Column(
		modifier = modifier
			.fillMaxSize()
			.background(MaterialTheme.colors.background)
			.padding(16.dp)
	) {
		// Header
		Text(
			text = "Zcash Note Sync",
			style = SignerTypeface.TitleL,
			color = MaterialTheme.colors.primary,
			modifier = Modifier.padding(bottom = 16.dp)
		)

		// Scrollable content
		Column(
			modifier = Modifier
				.weight(1f)
				.verticalScroll(rememberScrollState()),
			verticalArrangement = Arrangement.spacedBy(12.dp)
		) {
			// Status card
			Column(
				modifier = Modifier
					.fillMaxWidth()
					.clip(RoundedCornerShape(12.dp))
					.background(MaterialTheme.colors.fill6)
					.padding(16.dp),
				verticalArrangement = Arrangement.spacedBy(8.dp)
			) {
				Text(
					text = "Verified",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary
				)
				Text(
					text = "${result.notesVerified} note${if (result.notesVerified.toInt() == 1) "" else "s"} verified",
					style = SignerTypeface.TitleS,
					color = MaterialTheme.colors.primary
				)
			}

			// Balance card
			Column(
				modifier = Modifier
					.fillMaxWidth()
					.clip(RoundedCornerShape(12.dp))
					.background(MaterialTheme.colors.fill6)
					.padding(16.dp),
				verticalArrangement = Arrangement.spacedBy(8.dp)
			) {
				Text(
					text = "Verified Balance",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary
				)
				Text(
					text = formatZec(result.totalBalance),
					style = SignerTypeface.TitleL,
					color = MaterialTheme.colors.primary
				)
			}

			// Network badge
			Column(
				modifier = Modifier
					.fillMaxWidth()
					.clip(RoundedCornerShape(8.dp))
					.background(MaterialTheme.colors.fill6)
					.padding(12.dp),
				verticalArrangement = Arrangement.spacedBy(4.dp)
			) {
				Text(
					text = if (result.mainnet) "Mainnet" else "Testnet",
					style = SignerTypeface.LabelM,
					color = MaterialTheme.colors.textTertiary
				)
				Text(
					text = "Anchor height: ${NumberFormat.getNumberInstance(Locale.US).format(result.anchorHeight.toLong())}",
					style = SignerTypeface.CaptionM,
					color = MaterialTheme.colors.textSecondary
				)
				Text(
					text = "Anchor: ${result.anchorHex.take(16)}...",
					style = SignerTypeface.CaptionM,
					color = MaterialTheme.colors.textSecondary
				)
			}

			// Anchor attestation status
			Column(
				modifier = Modifier
					.fillMaxWidth()
					.clip(RoundedCornerShape(8.dp))
					.background(MaterialTheme.colors.fill6)
					.padding(12.dp),
				verticalArrangement = Arrangement.spacedBy(4.dp)
			) {
				Text(
					text = if (result.anchorVerified) "Anchor: Attested by threshold group"
						else "Anchor: From zcli (single-signer)",
					style = SignerTypeface.LabelM,
					color = if (result.anchorVerified) MaterialTheme.colors.primary
						else MaterialTheme.colors.textTertiary
				)
				if (!result.anchorVerified) {
					Text(
						text = "No FROST wallet — anchor trust relies on zcli. Set up a threshold wallet for independent verification.",
						style = SignerTypeface.CaptionM,
						color = MaterialTheme.colors.textTertiary
					)
				}
			}
		}

		SignerDivider()
		Spacer(modifier = Modifier.height(16.dp))

		PrimaryButtonWide(
			label = "Done",
			onClicked = onDone
		)
	}
}

private fun formatZec(zatoshis: ULong): String {
	val zec = zatoshis.toLong() / 100_000_000.0
	return "%.8f ZEC".format(zec)
}
