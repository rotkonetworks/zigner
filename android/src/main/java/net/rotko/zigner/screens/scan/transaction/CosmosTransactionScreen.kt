package net.rotko.zigner.screens.scan.transaction

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import net.rotko.zigner.R
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*
import io.parity.signer.uniffi.CosmosSignRequest

/**
 * Cosmos transaction signing screen
 * Displays amino sign doc details and allows user to approve/decline
 */
@Composable
fun CosmosTransactionScreen(
	request: CosmosSignRequest,
	onApprove: Callback,
	onDecline: Callback,
	modifier: Modifier = Modifier,
) {
	val hasBlindMsgs = request.msgs.any { it.blind }

	Column(
		modifier = modifier
			.fillMaxSize()
			.background(MaterialTheme.colors.background)
			.padding(16.dp)
	) {
		// Header
		Text(
			text = "Cosmos Transaction",
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
			// Chain
			CosmosInfoCard(
				label = "Chain",
				value = request.chainName.ifEmpty { request.chainId.ifEmpty { "Unknown" } }
			)

			// Blind signing warning — shown prominently before any message details
			if (hasBlindMsgs) {
				CosmosWarningCard(
					"BLIND SIGNING REQUIRED",
					"This transaction contains message types that cannot be fully " +
						"verified by the wallet. You are trusting the transaction " +
						"source. Review all details carefully before signing."
				)
			}

			// Show ALL messages — never hide messages from the user
			val msgCount = request.msgs.size
			if (msgCount > 1) {
				CosmosInfoCard(
					label = "WARNING",
					value = "This transaction contains $msgCount messages. Review ALL of them carefully."
				)
			}

			request.msgs.forEachIndexed { index, msg ->
				val prefix = if (msgCount > 1) "Message ${index + 1}/$msgCount: " else ""

				if (msg.blind) {
					CosmosWarningCard(
						label = "${prefix}${msg.msgType}",
						value = "Cannot verify — blind signing required"
					)
				} else {
					CosmosInfoCard(
						label = "${prefix}Type",
						value = msg.msgType.ifEmpty { "Unknown" }
					)
				}

				if (msg.recipient.isNotEmpty()) {
					CosmosInfoCard(label = "${prefix}Recipient", value = msg.recipient)
				}

				if (msg.amount.isNotEmpty()) {
					CosmosInfoCard(label = "${prefix}Amount", value = msg.amount)
				}

				if (msg.detail.isNotEmpty()) {
					CosmosInfoCard(label = "${prefix}Detail", value = msg.detail)
				}

				if (index < msgCount - 1) {
					SignerDivider()
				}
			}

			if (msgCount == 0) {
				CosmosInfoCard(label = "Type", value = "Unknown (no messages)")
			}

			// Fee
			if (request.fee.isNotEmpty()) {
				CosmosInfoCard(label = "Fee", value = request.fee)
			}

			// Memo
			if (request.memo.isNotEmpty()) {
				CosmosInfoCard(label = "Memo", value = request.memo)
			}

			// Chain ID (technical detail)
			if (request.chainId.isNotEmpty()) {
				CosmosInfoCard(label = "Chain ID", value = request.chainId)
			}
		}

		SignerDivider()
		Spacer(modifier = Modifier.height(16.dp))

		// Action buttons
		Column(
			verticalArrangement = Arrangement.spacedBy(8.dp)
		) {
			PrimaryButtonWide(
				label = if (hasBlindMsgs) {
					"Sign (Blind)"
				} else {
					stringResource(R.string.transaction_action_approve)
				},
				onClicked = onApprove
			)
			SecondaryButtonWide(
				label = stringResource(R.string.transaction_action_decline),
				onClicked = onDecline
			)
		}
	}
}

@Composable
private fun CosmosInfoCard(label: String, value: String) {
	Column(
		modifier = Modifier
			.fillMaxWidth()
			.clip(RoundedCornerShape(8.dp))
			.background(MaterialTheme.colors.fill6)
			.padding(12.dp),
		verticalArrangement = Arrangement.spacedBy(4.dp)
	) {
		Text(
			text = label,
			style = SignerTypeface.LabelM,
			color = MaterialTheme.colors.textTertiary
		)
		Text(
			text = value,
			style = SignerTypeface.BodyL,
			color = MaterialTheme.colors.primary
		)
	}
}

@Composable
private fun CosmosWarningCard(label: String, value: String) {
	Column(
		modifier = Modifier
			.fillMaxWidth()
			.clip(RoundedCornerShape(8.dp))
			.background(MaterialTheme.colors.backgroundDanger)
			.padding(12.dp),
		verticalArrangement = Arrangement.spacedBy(4.dp)
	) {
		Text(
			text = label,
			style = SignerTypeface.LabelM,
			color = MaterialTheme.colors.accentRed
		)
		Text(
			text = value,
			style = SignerTypeface.BodyL,
			color = MaterialTheme.colors.accentRed
		)
	}
}
