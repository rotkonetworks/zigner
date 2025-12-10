package net.rotko.zigner.screens.scan.transaction.transactionElements

import androidx.compose.foundation.layout.Row
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import net.rotko.zigner.R
import net.rotko.zigner.components.networkicon.IdentIconImage
import io.parity.signer.uniffi.MTypesInfo

@Composable
fun TCTypesInfo(types: MTypesInfo) {
	Row {
		types.typesIdPic?.let {
			IdentIconImage(identicon = it)
		}
		TCNameValueElement(
			name = stringResource(R.string.transaction_types_info_hash),
			value = types.typesHash ?: ""
		)
	}
}
