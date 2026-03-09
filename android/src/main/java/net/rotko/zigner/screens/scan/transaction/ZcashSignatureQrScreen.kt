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
 * Screen to display Zcash signature QR code after signing
 */
@Composable
fun ZcashSignatureQrScreen(
    signatureBytes: ByteArray,
    onDone: Callback,
    modifier: Modifier = Modifier,
) {
    // Encode as hex string for QR — avoids binary charset corruption issues
    // when zafu's QR scanner (ZXing) decodes byte-mode QR data
    val hexString = signatureBytes.joinToString("") { String.format("%02x", it) }
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
            text = "Zcash Signature",
            style = SignerTypeface.TitleL,
            color = MaterialTheme.colors.primary,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        Text(
            text = "Scan this QR code with Zafu to complete the transaction",
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
