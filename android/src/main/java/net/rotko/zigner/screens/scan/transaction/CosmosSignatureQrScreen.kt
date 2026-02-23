package net.rotko.zigner.screens.scan.transaction

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import net.rotko.zigner.R
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.components.qrcode.AnimatedQrKeysInfo
import net.rotko.zigner.components.qrcode.EmptyQrCodeProvider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*

/**
 * Screen to display Cosmos signature QR code after signing
 * Shows hex-encoded 64-byte secp256k1 signature for Zafu to scan
 */
@Composable
fun CosmosSignatureQrScreen(
	signatureBytes: ByteArray,
	onDone: Callback,
	modifier: Modifier = Modifier,
) {
	// Hex-encode the 64-byte signature for QR display
	val hexString = signatureBytes.joinToString("") { "%02x".format(it) }
	val qrData: List<List<UByte>> = listOf(hexString.toByteArray(Charsets.US_ASCII).map { it.toUByte() })

	Column(
		modifier = modifier
			.fillMaxSize()
			.background(MaterialTheme.colors.background)
			.padding(16.dp),
		horizontalAlignment = Alignment.CenterHorizontally
	) {
		// Header
		Text(
			text = "Cosmos Signature",
			style = SignerTypeface.TitleL,
			color = MaterialTheme.colors.primary,
			modifier = Modifier.padding(bottom = 8.dp)
		)

		Text(
			text = "Scan this QR code with Zafu to broadcast the transaction",
			style = SignerTypeface.BodyL,
			color = MaterialTheme.colors.textSecondary,
			modifier = Modifier.padding(bottom = 24.dp)
		)

		// QR Code display
		Box(
			modifier = Modifier
				.weight(1f)
				.fillMaxWidth(),
			contentAlignment = Alignment.Center
		) {
			AnimatedQrKeysInfo<List<List<UByte>>>(
				input = qrData,
				provider = EmptyQrCodeProvider(),
				modifier = Modifier
					.fillMaxWidth()
					.padding(horizontal = 24.dp)
			)
		}

		SignerDivider()
		Spacer(modifier = Modifier.height(16.dp))

		PrimaryButtonWide(
			label = stringResource(R.string.generic_done),
			onClicked = onDone
		)
	}
}
