package net.rotko.zigner.screens.settings.zcashfvk

import android.content.res.Configuration
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
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
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import net.rotko.zigner.components.base.ScreenHeaderClose
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.intoImageBitmap
import net.rotko.zigner.ui.theme.*
import kotlinx.coroutines.launch

@Composable
fun ZcashFvkExportIntegratedScreen(
    coreNavController: NavController,
    onBack: Callback
) {
    val viewModel = viewModel<ZcashFvkExportViewModel>()
    val seeds = viewModel.getSeeds()
    var selectedSeed by remember { mutableStateOf<String?>(null) }
    var exportResult by remember { mutableStateOf<ZcashFvkExportResult?>(null) }
    var isLoading by remember { mutableStateOf(false) }
    var isMainnet by remember { mutableStateOf(true) }
    val scope = rememberCoroutineScope()

    Box(modifier = Modifier.statusBarsPadding()) {
        if (exportResult != null) {
            // Show QR code result
            ZcashFvkExportResultView(
                result = exportResult!!,
                onBack = {
                    exportResult = null
                    selectedSeed = null
                }
            )
        } else if (selectedSeed != null) {
            // Loading state while exporting
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colors.background),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Text(
                    text = "Exporting Zcash Viewing Key...",
                    style = SignerTypeface.TitleS,
                    color = MaterialTheme.colors.primary
                )
            }
        } else {
            // Show seed selector
            ZcashFvkSeedSelectorScreen(
                seeds = seeds,
                isMainnet = isMainnet,
                onMainnetChanged = { isMainnet = it },
                onBack = onBack,
                onSeedSelected = { seedName ->
                    selectedSeed = seedName
                    isLoading = true
                    scope.launch {
                        val result = viewModel.exportFvk(seedName, 0u, seedName, isMainnet)
                        exportResult = result
                        isLoading = false
                        if (result == null) {
                            selectedSeed = null
                        }
                    }
                }
            )
        }
    }
}

@Composable
private fun ZcashFvkSeedSelectorScreen(
    seeds: List<String>,
    isMainnet: Boolean,
    onMainnetChanged: (Boolean) -> Unit,
    onBack: Callback,
    onSeedSelected: (String) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colors.background)
    ) {
        ScreenHeaderClose(
            title = "Export Zcash FVK",
            onClose = onBack
        )

        Text(
            text = "Select a wallet to export its Orchard Full Viewing Key for Zafu/Prax:",
            style = SignerTypeface.BodyL,
            color = MaterialTheme.colors.textSecondary,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)
        )

        // Network toggle
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp, vertical = 8.dp),
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
                onCheckedChange = onMainnetChanged
            )
        }

        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
        ) {
            seeds.forEach { seedName ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onSeedSelected(seedName) }
                        .padding(horizontal = 24.dp, vertical = 16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = seedName,
                        style = SignerTypeface.TitleS,
                        color = MaterialTheme.colors.primary,
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }

        Text(
            text = "The FVK allows viewing your Zcash Orchard transaction history without spending ability. Safe to share with watch-only wallets.",
            style = SignerTypeface.CaptionM,
            color = MaterialTheme.colors.textTertiary,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)
        )
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
@Composable
private fun ZcashFvkExportResultView(
    result: ZcashFvkExportResult,
    onBack: Callback
) {
    val qrBitmap = remember(result.qrPng) {
        result.qrPng.intoImageBitmap()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colors.background)
    ) {
        ScreenHeaderClose(
            title = "Zcash Full Viewing Key",
            onClose = onBack
        )

        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(16.dp))

            // Network indicator
            Text(
                text = if (result.mainnet) "Mainnet" else "Testnet",
                style = SignerTypeface.LabelM,
                color = if (result.mainnet) Color(0xFF3498db) else Color(0xFFe74c3c),
                modifier = Modifier
                    .clip(RoundedCornerShape(4.dp))
                    .background(MaterialTheme.colors.fill6)
                    .padding(horizontal = 8.dp, vertical = 4.dp)
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
                    contentDescription = "Zcash Full Viewing Key QR",
                    contentScale = ContentScale.Fit,
                    modifier = Modifier.fillMaxSize()
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                text = "Scan with Zafu or Prax to import",
                style = SignerTypeface.TitleS,
                color = MaterialTheme.colors.primary
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Address
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colors.fill6)
                    .padding(12.dp)
            ) {
                Text(
                    text = "Unified Address",
                    style = SignerTypeface.LabelM,
                    color = MaterialTheme.colors.textTertiary
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = result.address.take(24) + "...",
                    style = SignerTypeface.CaptionM,
                    color = MaterialTheme.colors.textSecondary
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            // FVK (truncated)
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colors.fill6)
                    .padding(12.dp)
            ) {
                Text(
                    text = "Orchard FVK",
                    style = SignerTypeface.LabelM,
                    color = MaterialTheme.colors.textTertiary
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = result.fvkHex.take(32) + "...",
                    style = SignerTypeface.CaptionM,
                    color = MaterialTheme.colors.textSecondary
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "This key allows viewing your Zcash Orchard transactions and balances. It cannot be used to spend funds.",
                style = SignerTypeface.CaptionM,
                color = MaterialTheme.colors.textTertiary,
                modifier = Modifier.padding(horizontal = 8.dp)
            )

            Spacer(modifier = Modifier.height(16.dp))
        }
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
private fun PreviewZcashFvkSeedSelector() {
    SignerNewTheme {
        ZcashFvkSeedSelectorScreen(
            seeds = listOf("My Wallet", "Cold Storage", "Testing"),
            isMainnet = true,
            onMainnetChanged = {},
            onBack = {},
            onSeedSelected = {}
        )
    }
}
