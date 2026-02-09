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
import io.parity.signer.uniffi.PenumbraSignRequest

/**
 * Penumbra transaction signing screen
 * Displays transaction details and allows user to approve/decline
 */
@Composable
fun PenumbraTransactionScreen(
	request: PenumbraSignRequest,
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
			text = "Penumbra Transaction",
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
			// Chain ID
			InfoCard(label = "Chain", value = request.chainId.ifEmpty { "Unknown" })

			// Effect hash
			InfoCard(
				label = "Effect Hash",
				value = if (request.effectHashHex.length > 16)
					request.effectHashHex.take(8) + "..." + request.effectHashHex.takeLast(8)
				else
					request.effectHashHex.ifEmpty { "N/A" }
			)

			// Actions summary
			Column(
				modifier = Modifier
					.fillMaxWidth()
					.clip(RoundedCornerShape(12.dp))
					.background(MaterialTheme.colors.fill6)
					.padding(16.dp),
				verticalArrangement = Arrangement.spacedBy(8.dp)
			) {
				Text(
					text = "Actions",
					style = SignerTypeface.TitleS,
					color = MaterialTheme.colors.primary
				)

				if (request.spendCount > 0u) {
					Text(
						text = "${request.spendCount} Spend${if (request.spendCount > 1u) "s" else ""}",
						style = SignerTypeface.BodyL,
						color = MaterialTheme.colors.textSecondary
					)
				}

				if (request.voteCount > 0u) {
					Text(
						text = "${request.voteCount} Delegator Vote${if (request.voteCount > 1u) "s" else ""}",
						style = SignerTypeface.BodyL,
						color = MaterialTheme.colors.textSecondary
					)
				}

				if (request.lqtVoteCount > 0u) {
					Text(
						text = "${request.lqtVoteCount} LQT Vote${if (request.lqtVoteCount > 1u) "s" else ""}",
						style = SignerTypeface.BodyL,
						color = MaterialTheme.colors.textSecondary
					)
				}

				val totalSigs = request.spendCount + request.voteCount + request.lqtVoteCount
				Text(
					text = "$totalSigs signature${if (totalSigs > 1u) "s" else ""} required",
					style = SignerTypeface.CaptionM,
					color = MaterialTheme.colors.textTertiary
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

@Composable
private fun InfoCard(label: String, value: String) {
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
