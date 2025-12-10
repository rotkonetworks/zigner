package net.rotko.zigner.screens.settings.general

import android.content.res.Configuration
import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview
import net.rotko.zigner.components.base.BottomSheetConfirmDialog
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.SignerNewTheme


@Composable
internal fun ConfirmOnlineModeBottomSheet(
	onCancel: Callback,
	onConfirm: Callback,
) {
	BottomSheetConfirmDialog(
		title = "Enable Online Mode?",
		message = "Online mode allows using Zigner with WiFi, Bluetooth, and other radios enabled.\n\n" +
			"⚠️ WARNING: This reduces the security of your cold wallet. " +
			"Only enable this if you understand the risks and need to use Zigner in a connected environment.\n\n" +
			"Your keys remain secure in hardware, but network exposure increases attack surface.",
		ctaLabel = "Enable Online Mode",
		onCancel = onCancel,
		isCtaDangerous = true,
		onCta = onConfirm,
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
private fun PreviewConfirmOnlineModeBottomSheet() {
	SignerNewTheme {
		ConfirmOnlineModeBottomSheet(
			{}, {},
		)
	}
}
