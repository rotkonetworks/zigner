package net.rotko.zigner.screens.scan.transaction.transactionElements

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import net.rotko.zigner.R
import net.rotko.zigner.components.networkicon.IdentIconImage
import net.rotko.zigner.ui.theme.*
import io.parity.signer.uniffi.MVerifierDetails

@Composable
fun TCAuthorPublicKey(key: MVerifierDetails) {
	Row {
		IdentIconImage(identicon = key.identicon)
		Column {
			Text(
				stringResource(R.string.transaction_field_signed_with, key.encryption),
				style = SignerTypeface.BodyL,
				color = MaterialTheme.colors.textTertiary
			)
			Text(
				key.publicKey,
				style = SignerTypeface.CaptionM,
				color = MaterialTheme.colors.pink300
			)
		}
	}
}
