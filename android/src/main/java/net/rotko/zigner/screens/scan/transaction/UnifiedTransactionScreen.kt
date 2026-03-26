package net.rotko.zigner.screens.scan.transaction

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Tab
import androidx.compose.material.TabRow
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.ScreenHeader
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*

/**
 * Unified transaction signing screen.
 * Renders different content based on network type (Penumbra, Cosmos, Zcash).
 * Has Simple (human-readable) and Complex (raw payload) tabs.
 */
@Composable
fun UnifiedTransactionScreen(
	signRequest: SignRequest,
	onApprove: Callback,
	onDecline: Callback,
	modifier: Modifier = Modifier,
) {
	var selectedTab by remember { mutableStateOf(0) }
	val tabs = listOf("Simple", "Complex")

	Column(
		modifier = modifier
			.fillMaxSize()
			.background(MaterialTheme.colors.backgroundPrimary)
	) {
		ScreenHeader(
			title = "${signRequest.networkName} Transaction",
			onBack = onDecline,
		)

		// Tab row
		TabRow(
			selectedTabIndex = selectedTab,
			backgroundColor = MaterialTheme.colors.backgroundPrimary,
			contentColor = MaterialTheme.colors.primary,
			modifier = Modifier.padding(horizontal = 16.dp),
		) {
			tabs.forEachIndexed { index, title ->
				Tab(
					selected = selectedTab == index,
					onClick = { selectedTab = index },
					text = {
						Text(
							text = title,
							style = SignerTypeface.LabelM,
							color = if (selectedTab == index)
								MaterialTheme.colors.primary
							else
								MaterialTheme.colors.textTertiary,
						)
					}
				)
			}
		}

		// Tab content
		Column(
			modifier = Modifier
				.weight(1f)
				.verticalScroll(rememberScrollState())
				.padding(16.dp),
			verticalArrangement = Arrangement.spacedBy(12.dp),
		) {
			when (selectedTab) {
				0 -> SimpleTabContent(signRequest)
				1 -> ComplexTabContent(signRequest)
			}
		}

		// Action buttons
		Column(
			modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp),
			verticalArrangement = Arrangement.spacedBy(8.dp),
		) {
			PrimaryButtonWide(
				label = "Approve & Sign",
				onClicked = onApprove,
			)
			SecondaryButtonWide(
				label = "Decline",
				onClicked = onDecline,
			)
		}
	}
}

// =============================================================================
// Simple tab — human-readable summary per network
// =============================================================================

@Composable
private fun SimpleTabContent(signRequest: SignRequest) {
	when (signRequest) {
		is SignRequest.Penumbra -> PenumbraSimpleContent(signRequest)
		is SignRequest.Cosmos -> CosmosSimpleContent(signRequest)
		is SignRequest.ZcashSimple -> ZcashSimpleContent(signRequest)
		is SignRequest.ZcashPczt -> ZcashPcztSimpleContent(signRequest)
	}
}

@Composable
private fun PenumbraSimpleContent(req: SignRequest.Penumbra) {
	val r = req.request
	InfoCard(label = "Chain", value = r.chainId.ifEmpty { "Unknown" })
	InfoCard(
		label = "Effect Hash",
		value = if (r.effectHashHex.length > 16)
			r.effectHashHex.take(8) + "..." + r.effectHashHex.takeLast(8)
		else r.effectHashHex.ifEmpty { "N/A" }
	)
	InfoCard(label = "Spends", value = "${r.spendCount}")
	if (r.voteCount > 0u) {
		InfoCard(label = "Delegator Votes", value = "${r.voteCount}")
	}
	if (r.lqtVoteCount > 0u) {
		InfoCard(label = "LQT Votes", value = "${r.lqtVoteCount}")
	}
	val totalSigs = r.spendCount + r.voteCount + r.lqtVoteCount
	InfoCard(label = "Total Signatures", value = "$totalSigs")
}

@Composable
private fun CosmosSimpleContent(req: SignRequest.Cosmos) {
	val r = req.request
	InfoCard(label = "Chain", value = r.chainName.ifEmpty { r.chainId })

	// Blind signing warning
	if (r.msgs.any { it.blind }) {
		WarningCard("This transaction contains unrecognized message types. Review carefully.")
	}

	// Messages
	r.msgs.forEachIndexed { i, msg ->
		Column(
			modifier = Modifier
				.fillMaxWidth()
				.clip(RoundedCornerShape(12.dp))
				.background(MaterialTheme.colors.fill6)
				.padding(12.dp),
			verticalArrangement = Arrangement.spacedBy(4.dp),
		) {
			if (r.msgs.size > 1) {
				Text(
					text = "Message ${i + 1}/${r.msgs.size}",
					style = SignerTypeface.CaptionM,
					color = MaterialTheme.colors.textTertiary,
				)
			}
			Text(text = msg.msgType, style = SignerTypeface.LabelM, color = MaterialTheme.colors.primary)
			if (msg.recipient.isNotEmpty()) {
				Text(text = "To: ${msg.recipient.take(20)}...", style = SignerTypeface.CaptionM, color = MaterialTheme.colors.textSecondary)
			}
			if (msg.amount.isNotEmpty()) {
				Text(text = msg.amount, style = SignerTypeface.BodyL, color = MaterialTheme.colors.primary)
			}
			if (msg.detail.isNotEmpty()) {
				Text(text = msg.detail, style = SignerTypeface.CaptionM, color = MaterialTheme.colors.textSecondary)
			}
			if (msg.blind) {
				Text(text = "⚠ Blind signing required", style = SignerTypeface.CaptionM, color = Color(0xFFe74c3c))
			}
		}
	}

	InfoCard(label = "Fee", value = r.fee)
	if (r.memo.isNotEmpty()) {
		InfoCard(label = "Memo", value = r.memo)
	}
}

@Composable
private fun ZcashSimpleContent(req: SignRequest.ZcashSimple) {
	val r = req.request

	// Network badge
	Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
		Text(text = "Zcash", style = SignerTypeface.TitleS, color = MaterialTheme.colors.primary)
		Text(
			text = if (r.mainnet) "Mainnet" else "Testnet",
			style = SignerTypeface.LabelM,
			color = if (r.mainnet) Color(0xFF3498db) else Color(0xFFe74c3c),
			modifier = Modifier
				.clip(RoundedCornerShape(4.dp))
				.background(MaterialTheme.colors.fill6)
				.padding(horizontal = 6.dp, vertical = 2.dp),
		)
	}

	// Summary from zafu
	if (r.summary.isNotEmpty()) {
		InfoCard(label = "Summary", value = r.summary)
	}

	InfoCard(label = "Actions", value = "${r.actionCount} orchard action(s)")
	InfoCard(label = "Account", value = "#${r.accountIndex}")
	InfoCard(
		label = "Sighash",
		value = if (r.sighashHex.length > 16)
			r.sighashHex.take(8) + "..." + r.sighashHex.takeLast(8)
		else r.sighashHex
	)
}

@Composable
private fun ZcashPcztSimpleContent(req: SignRequest.ZcashPczt) {
	val inspection = req.inspection
	if (inspection == null) {
		Text(text = "Inspecting PCZT...", style = SignerTypeface.BodyL, color = MaterialTheme.colors.textTertiary)
		return
	}

	InfoCard(label = "Actions", value = "${inspection.actionCount}")
	InfoCard(label = "Anchor", value = inspection.anchorHex.take(16) + "...")

	if (inspection.spends.isNotEmpty()) {
		Text(text = "Spends", style = SignerTypeface.LabelM, color = MaterialTheme.colors.pink300)
		inspection.spends.forEach { spend ->
			val zatoshis = spend.value.toLong()
			val zec = "%.8f".format(zatoshis / 100_000_000.0)
			InfoCard(
				label = if (spend.known) "Verified Spend" else "⚠ Unknown Spend",
				value = "$zec ZEC"
			)
		}
	}

	if (inspection.outputs.isNotEmpty()) {
		Text(text = "Outputs", style = SignerTypeface.LabelM, color = MaterialTheme.colors.Crypto400)
		inspection.outputs.forEach { output ->
			val zatoshis = output.value.toLong()
			val zec = "%.8f".format(zatoshis / 100_000_000.0)
			InfoCard(label = output.recipient.take(20) + "...", value = "$zec ZEC")
		}
	}

	val feeZec = "%.8f".format(inspection.netValue / 100_000_000.0)
	InfoCard(label = "Fee", value = "$feeZec ZEC")

	if (!inspection.anchorMatches) {
		WarningCard("Anchor does not match verified state. Proceed with caution.")
	}
}

// =============================================================================
// Complex tab — raw payload
// =============================================================================

@Composable
private fun ComplexTabContent(signRequest: SignRequest) {
	Text(
		text = "Raw Payload",
		style = SignerTypeface.LabelM,
		color = MaterialTheme.colors.textTertiary,
		modifier = Modifier.padding(bottom = 4.dp),
	)

	val payload = signRequest.rawPayload
	if (payload.isEmpty()) {
		Text(
			text = "(no raw payload available)",
			style = SignerTypeface.CaptionM,
			color = MaterialTheme.colors.textTertiary,
		)
	} else {
		Text(
			text = payload,
			style = SignerTypeface.CaptionM.copy(fontFamily = FontFamily.Monospace),
			color = MaterialTheme.colors.textSecondary,
			modifier = Modifier
				.fillMaxWidth()
				.clip(RoundedCornerShape(8.dp))
				.background(MaterialTheme.colors.fill6)
				.padding(12.dp),
		)
	}
}

// =============================================================================
// Shared composables
// =============================================================================

@Composable
private fun InfoCard(label: String, value: String) {
	Column(
		modifier = Modifier
			.fillMaxWidth()
			.clip(RoundedCornerShape(8.dp))
			.background(MaterialTheme.colors.fill6)
			.padding(12.dp),
		verticalArrangement = Arrangement.spacedBy(4.dp),
	) {
		Text(text = label, style = SignerTypeface.CaptionM, color = MaterialTheme.colors.textTertiary)
		Text(text = value, style = SignerTypeface.BodyL, color = MaterialTheme.colors.primary)
	}
}

@Composable
private fun WarningCard(message: String) {
	Column(
		modifier = Modifier
			.fillMaxWidth()
			.clip(RoundedCornerShape(8.dp))
			.background(Color(0x33E74C3C))
			.padding(12.dp),
	) {
		Text(text = message, style = SignerTypeface.CaptionM, color = Color(0xFFE74C3C))
	}
}
