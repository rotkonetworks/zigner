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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import net.rotko.zigner.R
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.screens.scan.transaction.transactionElements.TCZcashOrchardSpend
import net.rotko.zigner.screens.scan.transaction.transactionElements.TCZcashSummary
import net.rotko.zigner.ui.theme.*
import io.parity.signer.uniffi.ZcashOrchardSpend
import io.parity.signer.uniffi.ZcashSignRequest
import io.parity.signer.uniffi.ZcashTransactionSummary
import io.parity.signer.uniffi.getZcashVerifiedBalance
import io.parity.signer.uniffi.getZcashSyncInfo

/**
 * Zcash transaction signing screen
 * Displays transaction details and allows user to approve/decline
 */
@Composable
fun ZcashTransactionScreen(
    request: ZcashSignRequest,
    onApprove: Callback,
    onDecline: Callback,
    modifier: Modifier = Modifier,
) {
    // Load verified balance for context
    val verifiedBalance = remember {
        try { getZcashVerifiedBalance() } catch (_: Exception) { null }
    }
    val syncInfo = remember {
        try { getZcashSyncInfo() } catch (_: Exception) { null }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colors.background)
            .padding(16.dp)
    ) {
        // Header
        Text(
            text = "Zcash Transaction",
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
            // Verified balance context
            // Blind signing warning
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(MaterialTheme.colors.red500fill12)
                    .padding(12.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.Top,
            ) {
                Text(text = "\u26A0", style = SignerTypeface.TitleS)
                Column {
                    Text(
                        text = "Blind signing mode",
                        style = SignerTypeface.LabelM,
                        color = MaterialTheme.colors.red500
                    )
                    Text(
                        text = "Transaction details cannot be verified. Use PCZT (ur:zcash-pczt) for inspectable signing.",
                        style = SignerTypeface.CaptionM,
                        color = MaterialTheme.colors.textSecondary
                    )
                }
            }

            if (verifiedBalance != null) {
                val zec = verifiedBalance.toLong() / 100_000_000.0
                val syncedAt = syncInfo?.syncedAt?.toLong() ?: 0L
                val now = System.currentTimeMillis() / 1000
                val diff = now - syncedAt
                val timeAgo = when {
                    syncedAt == 0L -> ""
                    diff < 60 -> "just now"
                    diff < 3600 -> "${diff / 60}m ago"
                    diff < 86400 -> "${diff / 3600}h ago"
                    diff < 604800 -> "${diff / 86400}d ago"
                    else -> "${diff / 604800}w ago"
                }
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colors.fill6)
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = "Verified Balance",
                            style = SignerTypeface.LabelM,
                            color = MaterialTheme.colors.textTertiary
                        )
                        if (timeAgo.isNotEmpty()) {
                            Text(
                                text = timeAgo,
                                style = SignerTypeface.CaptionM,
                                color = if (diff > 86400) MaterialTheme.colors.red500 else MaterialTheme.colors.textTertiary
                            )
                        }
                    }
                    Text(
                        text = "%.8f ZEC".format(zec),
                        style = SignerTypeface.TitleS,
                        color = MaterialTheme.colors.primary
                    )
                }
            } else {
                // Warning: no verified balance
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colors.red500fill12)
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(text = "\u26A0", style = SignerTypeface.TitleS)
                    Column {
                        Text(
                            text = "No verified balance",
                            style = SignerTypeface.LabelM,
                            color = MaterialTheme.colors.red500
                        )
                        Text(
                            text = "Sync notes first: zcli export-notes \u2192 scan QR",
                            style = SignerTypeface.CaptionM,
                            color = MaterialTheme.colors.textSecondary
                        )
                    }
                }
            }

            // Transaction summary card
            TCZcashSummary(
                summary = ZcashTransactionSummary(
                    mainnet = request.mainnet,
                    fee = "see summary",
                    spendCount = request.alphas.size.toULong(),
                    outputCount = 0u,
                    sighash = request.sighash,
                    anchor = "provided by wallet"
                )
            )

            // Action cards for each alpha
            request.alphas.forEachIndexed { index, alpha ->
                TCZcashOrchardSpend(
                    spend = ZcashOrchardSpend(
                        nullifier = "action #${index + 1}",
                        value = "shielded",
                        cmx = alpha.take(32)
                    )
                )
            }

            // Summary text from wallet
            if (request.summary.isNotEmpty()) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colors.fill6)
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Transaction Summary",
                        style = SignerTypeface.TitleS,
                        color = MaterialTheme.colors.primary
                    )
                    Text(
                        text = request.summary,
                        style = SignerTypeface.BodyL,
                        color = MaterialTheme.colors.textSecondary
                    )
                }
            }

            // Account info
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(MaterialTheme.colors.fill6)
                    .padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = "Account #${request.accountIndex}",
                    style = SignerTypeface.LabelM,
                    color = MaterialTheme.colors.textTertiary
                )
                Text(
                    text = "${request.alphas.size} signature${if (request.alphas.size == 1) "" else "s"} required",
                    style = SignerTypeface.CaptionM,
                    color = MaterialTheme.colors.textSecondary
                )
            }
        }

        SignerDivider()
        Spacer(modifier = Modifier.height(16.dp))

        // Action buttons
        Column(
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            PrimaryButtonWide(
                label = stringResource(R.string.transaction_action_approve),
                onClicked = onApprove
            )
            SecondaryButtonWide(
                label = stringResource(R.string.transaction_action_decline),
                onClicked = onDecline
            )
        }
    }
}
