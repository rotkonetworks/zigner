package net.rotko.zigner.screens.scan.addnetwork

import android.annotation.SuppressLint
import android.content.res.Configuration
import androidx.compose.foundation.layout.*
import androidx.compose.material.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import net.rotko.zigner.R
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.networkicon.NetworkIcon
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.NetworkModel
import net.rotko.zigner.ui.theme.*


@Composable
fun AddNetworkToKeysetQuestionBottomSheet(
	networkModel: NetworkModel,
	onConfirm: Callback,
	onCancel: Callback,
) {
	val sidePadding = 24.dp
	Column(
		modifier = Modifier
			.fillMaxWidth()
			.padding(start = sidePadding, end = sidePadding),
		horizontalAlignment = Alignment.CenterHorizontally,
	) {
		NetworkIcon(
			networkLogoName = networkModel.logo,
			size = 80.dp,
			modifier = Modifier.padding(top = 40.dp)
		)
		Text(
			text = stringResource(
				R.string.add_network_add_keys_title,
				networkModel.title
			),
			color = MaterialTheme.colors.primary,
			style = SignerTypeface.TitleL,
			modifier = Modifier.padding(bottom = 16.dp, top = 24.dp)
		)

		PrimaryButtonWide(
			stringResource(R.string.add_network_add_keys_cta),
			onClicked = onConfirm,
		)

		Spacer(modifier = Modifier.padding(bottom = 8.dp))

		SecondaryButtonWide(
			stringResource(R.string.generic_cancel),
			onClicked = onCancel,
		)
		Spacer(modifier = Modifier.padding(bottom = 24.dp))
	}
}


@SuppressLint("UnrememberedMutableState")
@Preview(
	name = "light", group = "general", uiMode = Configuration.UI_MODE_NIGHT_NO,
	showBackground = true, backgroundColor = 0xFFFFFFFF,
)
@Preview(
	name = "dark", group = "general",
	uiMode = Configuration.UI_MODE_NIGHT_YES,
	showBackground = true, backgroundColor = 0xFF000000,
)
@Composable
private fun PreviewAddNetworkToKeysetBottomSheet() {
	SignerNewTheme {
		val network = NetworkModel.createStub()
		AddNetworkToKeysetQuestionBottomSheet(network, {}, {})
	}
}
