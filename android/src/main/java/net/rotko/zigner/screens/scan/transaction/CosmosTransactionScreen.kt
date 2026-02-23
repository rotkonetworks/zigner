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

			// Message type
			CosmosInfoCard(label = "Type", value = request.msgType.ifEmpty { "Unknown" })

			// Recipient
			if (request.recipient.isNotEmpty()) {
				CosmosInfoCard(label = "Recipient", value = request.recipient)
			}

			// Amount
			if (request.amount.isNotEmpty()) {
				CosmosInfoCard(label = "Amount", value = request.amount)
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
