package net.rotko.zigner.screens.settings.general

import android.content.res.Configuration
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import net.rotko.zigner.R
import net.rotko.zigner.components.base.BottomSheetConfirmDialog
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.SignerNewTheme


@Composable
internal fun ConfirmFactorySettingsBottomSheet(
	onCancel: Callback,
	onFactoryReset: Callback,
) {
	BottomSheetConfirmDialog(
		title = stringResource(R.string.confirm_factory_reset_title),
		message = stringResource(R.string.confirm_factory_reset_message),
		ctaLabel = stringResource(R.string.remove_key_set_confirm_cta),
		onCancel = onCancel,
		isCtaDangerous = true,
		onCta = onFactoryReset,
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
		ConfirmFactorySettingsBottomSheet(
			{}, {},
		)
	}
}


