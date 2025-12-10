package net.rotko.zigner.screens.settings.networks.details.menu

import android.content.res.Configuration
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import net.rotko.zigner.R
import net.rotko.zigner.components.base.BottomSheetConfirmDialog
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.SignerNewTheme


@Composable
fun ConfirmRemoveNetworkBottomSheet(
	onCancel: Callback,
	onRemoveNetwork: Callback,
) {
	BottomSheetConfirmDialog(
		title = stringResource(R.string.network_details_remove_confirm_title),
		message = stringResource(R.string.network_details_remove_confirm_description),
		ctaLabel = stringResource(R.string.remove_key_set_confirm_cta),
		isCtaDangerous = true,
		onCancel = onCancel,
		onCta = onRemoveNetwork,
	)
}


@Composable
fun ConfirmRemoveMetadataBottomSheet(
	onCancel: Callback,
	onRemoveMetadata: Callback,
) {
	BottomSheetConfirmDialog(
		title = stringResource(R.string.network_details_remove_metadata_confirm_title),
		message = stringResource(R.string.network_details_remove_metadata_confirm_description),
		ctaLabel = stringResource(R.string.remove_key_set_confirm_cta),
		onCancel = onCancel,
		isCtaDangerous = true,
		onCta = onRemoveMetadata,
	)
}


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
private fun PreviewConfirmRemoveNetworkBottomSheet() {
	SignerNewTheme {
		ConfirmRemoveNetworkBottomSheet(
			{}, {},
		)
	}
}


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
private fun PreviewConfirmRemoveMetadataBottomSheet() {
	SignerNewTheme {
		ConfirmRemoveMetadataBottomSheet(
			{}, {},
		)
	}
}
