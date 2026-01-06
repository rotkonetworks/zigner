package net.rotko.zigner.screens.settings.zcashfvk

import android.content.res.Configuration
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Slider
import androidx.compose.material.Switch
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.ScreenHeaderClose
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.intoImageBitmap
import net.rotko.zigner.ui.theme.*
import io.parity.signer.uniffi.generateTestZcashSignRequest
import io.parity.signer.uniffi.encodeToQr

/**
 * Test screen for generating Zcash sign request QR codes
 * This is for development/testing of the signing flow only
 */
@Composable
fun ZcashTestQrScreen(
    onBack: Callback
) {
    var accountIndex by remember { mutableStateOf(0) }
    var actionCount by remember { mutableStateOf(1) }
    var isMainnet by remember { mutableStateOf(true) }
    var summary by remember { mutableStateOf("Test send 1.5 ZEC") }
    var generatedQr by remember { mutableStateOf<ByteArray?>(null) }
    var qrHex by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colors.background)
            .statusBarsPadding()
    ) {
        ScreenHeaderClose(
            title = "Test Zcash Sign QR",
            onClose = onBack
        )

        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp)
        ) {
            if (generatedQr != null) {
                // Show generated QR
                ZcashTestQrResult(
                    qrBytes = generatedQr!!,
                    qrHex = qrHex ?: "",
                    onBack = {
                        generatedQr = null
                        qrHex = null
                    }
                )
            } else {
                // Show configuration form
                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "Generate a test Zcash sign request QR code for development testing",
                    style = SignerTypeface.BodyL,
                    color = MaterialTheme.colors.textSecondary
                )

                Spacer(modifier = Modifier.height(24.dp))

                // Account index
                Text(
                    text = "Account Index: $accountIndex",
                    style = SignerTypeface.LabelM,
                    color = MaterialTheme.colors.primary
                )
                Slider(
                    value = accountIndex.toFloat(),
                    onValueChange = { accountIndex = it.toInt() },
                    valueRange = 0f..10f,
                    steps = 9
                )

                Spacer(modifier = Modifier.height(16.dp))

                // Action count
                Text(
                    text = "Action Count (Orchard spends): $actionCount",
                    style = SignerTypeface.LabelM,
                    color = MaterialTheme.colors.primary
                )
                Slider(
                    value = actionCount.toFloat(),
                    onValueChange = { actionCount = it.toInt().coerceAtLeast(1) },
                    valueRange = 1f..5f,
                    steps = 3
                )

                Spacer(modifier = Modifier.height(16.dp))

                // Network toggle
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Network:",
                        style = SignerTypeface.LabelM,
                        color = MaterialTheme.colors.textSecondary,
                        modifier = Modifier.weight(1f)
                    )
                    Text(
                        text = if (isMainnet) "Mainnet" else "Testnet",
                        style = SignerTypeface.LabelM,
                        color = MaterialTheme.colors.primary
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Switch(
                        checked = isMainnet,
                        onCheckedChange = { isMainnet = it }
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Summary text
                Text(
                    text = "Transaction Summary",
                    style = SignerTypeface.LabelM,
                    color = MaterialTheme.colors.textSecondary
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = summary,
                    style = SignerTypeface.BodyL,
                    color = MaterialTheme.colors.primary,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(MaterialTheme.colors.fill6)
                        .padding(12.dp)
                )

                Spacer(modifier = Modifier.height(32.dp))

                // Generate button
                PrimaryButtonWide(
                    label = "Generate Test QR",
                    onClicked = {
                        try {
                            // Generate hex payload using FFI
                            val hexPayload = generateTestZcashSignRequest(
                                accountIndex.toUInt(),
                                actionCount.toUInt(),
                                isMainnet,
                                summary
                            )
                            qrHex = hexPayload

                            // Convert hex to bytes for QR encoding
                            val payloadBytes = hexPayload.chunked(2)
                                .map { it.toInt(16).toByte() }
                                .toByteArray()

                            // Encode as QR image
                            val qrPng = encodeToQr(payloadBytes.toList().map { it.toUByte() }, false)
                            generatedQr = qrPng.map { it.toByte() }.toByteArray()
                        } catch (e: Exception) {
                            // Handle error
                            e.printStackTrace()
                        }
                    }
                )

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "Scan the generated QR with the Zigner camera to test the signing flow",
                    style = SignerTypeface.CaptionM,
                    color = MaterialTheme.colors.textTertiary
                )

                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Composable
private fun ZcashTestQrResult(
    qrBytes: ByteArray,
    qrHex: String,
    onBack: Callback
) {
    val qrBitmap = remember(qrBytes) {
        qrBytes.toUByteArray().toList().intoImageBitmap()
    }

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Test Sign Request QR",
            style = SignerTypeface.TitleS,
            color = MaterialTheme.colors.primary
        )

        Spacer(modifier = Modifier.height(16.dp))

        // QR Code
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(1f)
                .clip(RoundedCornerShape(12.dp))
                .background(Color.White)
                .padding(16.dp),
            contentAlignment = Alignment.Center
        ) {
            Image(
                bitmap = qrBitmap,
                contentDescription = "Test Zcash sign request QR",
                contentScale = ContentScale.Fit,
                modifier = Modifier.fillMaxSize()
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Scan this QR with Zigner camera",
            style = SignerTypeface.BodyL,
            color = MaterialTheme.colors.textSecondary
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Show hex (truncated)
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colors.fill6)
                .padding(12.dp)
        ) {
            Text(
                text = "Payload (hex)",
                style = SignerTypeface.LabelM,
                color = MaterialTheme.colors.textTertiary
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = if (qrHex.length > 64) qrHex.take(64) + "..." else qrHex,
                style = SignerTypeface.CaptionM,
                color = MaterialTheme.colors.textSecondary
            )
        }

        Spacer(modifier = Modifier.height(24.dp))

        PrimaryButtonWide(
            label = "Generate Another",
            onClicked = onBack
        )
    }
}

@Preview(
    name = "light", group = "themes", uiMode = Configuration.UI_MODE_NIGHT_NO,
    showBackground = true, backgroundColor = 0xFFFFFFFF,
)
@Preview(
    name = "dark", group = "themes", uiMode = Configuration.UI_MODE_NIGHT_YES,
    showBackground = true, backgroundColor = 0xFF000000,
)
@Composable
private fun PreviewZcashTestQrScreen() {
    SignerNewTheme {
        ZcashTestQrScreen(onBack = {})
    }
}
