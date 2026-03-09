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
            // Transaction summary card
            val isShielding = request.shieldingSighashes.isNotEmpty()
            val sigCount = if (isShielding) request.shieldingSighashes.size else request.alphas.size
            TCZcashSummary(
                summary = ZcashTransactionSummary(
                    mainnet = request.mainnet,
                    fee = "see summary",
                    spendCount = sigCount.toULong(),
                    outputCount = 0u,
                    sighash = request.sighash,
                    anchor = if (isShielding) "shielding (transparent → orchard)" else "provided by wallet"
                )
            )

            if (isShielding) {
                // Shielding: show transparent input cards
                request.shieldingAddressIndices.forEachIndexed { index, addrIdx ->
                    TCZcashOrchardSpend(
                        spend = ZcashOrchardSpend(
                            nullifier = "transparent input #${index + 1}",
                            value = "address index $addrIdx",
                            cmx = request.shieldingSighashes.getOrElse(index) { "" }.take(32)
                        )
                    )
                }
            } else {
                // Orchard send: show action cards for each alpha
                request.alphas.forEachIndexed { index, alpha ->
                    TCZcashOrchardSpend(
                        spend = ZcashOrchardSpend(
                            nullifier = "action #${index + 1}",
                            value = "shielded",
                            cmx = alpha.take(32)
                        )
                    )
                }
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
                    text = "$sigCount ${if (isShielding) "transparent" else "orchard"} signature${if (sigCount == 1) "" else "s"} required",
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
