package net.rotko.zigner.screens.scan.transaction.transactionElements

import androidx.compose.foundation.layout.Row
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import net.rotko.zigner.R
import net.rotko.zigner.components.networkicon.IdentIconImage
import io.parity.signer.uniffi.MscId

@Composable
fun TCAuthorPlain(author: MscId) {
	Row {
		IdentIconImage(author.identicon)
		TCNameValueElement(
			name = stringResource(R.string.transaction_field_from),
			value = author.base58,
		)
	}
}
