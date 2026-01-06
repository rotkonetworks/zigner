package net.rotko.zigner.screens.keysetdetails.backup

import android.content.res.Configuration
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.QrCode
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import net.rotko.zigner.R
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.screens.keydetails.MenuItemForBottomSheet
import net.rotko.zigner.ui.theme.SignerNewTheme
import net.rotko.zigner.ui.theme.SignerTypeface
import net.rotko.zigner.ui.theme.textTertiary


@Composable
fun BackupMethodSelectBottomSheet(
	onManualBackup: Callback,
	onBananaSplit: Callback,
	onCancel: Callback,
) {
	val sidePadding = 24.dp
	Column(
		modifier = Modifier
			.fillMaxWidth()
			.padding(start = sidePadding, end = sidePadding, top = 8.dp),
	) {
		Text(
			text = stringResource(R.string.backup_method_title),
			style = SignerTypeface.TitleS,
			color = MaterialTheme.colors.primary,
			modifier = Modifier.padding(bottom = 16.dp)
		)

		MenuItemForBottomSheet(
			iconId = R.drawable.ic_settings_backup_restore_28,
			label = stringResource(R.string.key_set_menu_option_backup_manual),
			onclick = onManualBackup
		)
		Text(
			text = stringResource(R.string.backup_method_manual_desc),
			style = SignerTypeface.CaptionM,
			color = MaterialTheme.colors.textTertiary,
			modifier = Modifier.padding(start = 40.dp, bottom = 8.dp)
		)

		MenuItemForBottomSheet(
			vector = Icons.Outlined.QrCode,
			label = stringResource(R.string.key_set_menu_option_backup_bs),
			onclick = onBananaSplit
		)
		Text(
			text = stringResource(R.string.backup_method_bs_desc),
			style = SignerTypeface.CaptionM,
			color = MaterialTheme.colors.textTertiary,
			modifier = Modifier.padding(start = 40.dp, bottom = 16.dp)
		)

		SecondaryButtonWide(
			label = stringResource(R.string.generic_cancel),
			onClicked = onCancel
		)
		Spacer(modifier = Modifier.padding(bottom = 16.dp))
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
private fun PreviewBackupMethodSelect() {
	SignerNewTheme {
		BackupMethodSelectBottomSheet({}, {}, {})
	}
}
