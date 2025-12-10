package net.rotko.zigner.screens.keysetdetails.backup

import android.annotation.SuppressLint
import android.content.res.Configuration
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalInspectionMode
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import net.rotko.zigner.R
import net.rotko.zigner.components.base.BottomSheetHeader
import net.rotko.zigner.components.base.BottomSheetSubtitle
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.components.sharedcomponents.SnackBarCircularCountDownTimer
import net.rotko.zigner.domain.BASE58_STYLE_ABBREVIATE
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.KeySetDetailsModel
import net.rotko.zigner.domain.abbreviateString
import net.rotko.zigner.screens.keydetails.exportprivatekey.PrivateKeyExportModel
import net.rotko.zigner.screens.keysetdetails.items.SlimKeyItem
import net.rotko.zigner.ui.BottomSheetWrapperRoot
import net.rotko.zigner.ui.theme.SignerNewTheme


@Composable
fun KeySetBackupFullOverlayBottomSheet(
	model: SeedBackupModel,
	getSeedPhraseForBackup: suspend (String) -> String?,
	onClose: Callback,
) {
	val timerSize = remember {
		mutableStateOf(80.dp)
	}

	BottomSheetWrapperRoot(onClosedAction = onClose) {
		KeySetBackupBottomSheet(model, timerSize, getSeedPhraseForBackup, onClose)
	}
	Row(modifier = Modifier.fillMaxSize()) {
		SnackBarCircularCountDownTimer(
			PrivateKeyExportModel.SHOW_PRIVATE_KEY_TIMEOUT,
			stringResource(R.string.seed_backup_autohide_title),
			timerSize,
			Modifier.align(Alignment.Bottom),
			onClose,
		)
	}
}

@Composable
private fun KeySetBackupBottomSheet(
	model: SeedBackupModel,
	timerSize: State<Dp>,
	getSeedPhraseForBackup: suspend (String) -> String?,
	onClose: Callback,
) {
	var seedPhrase by remember { mutableStateOf("") }
	if (LocalInspectionMode.current) {
		seedPhrase = "sample test data set words for preview"
	}
	Column() {
		//header
		BottomSheetHeader(
			title = model.seedName,
			subtitile = model.seedBase58.abbreviateString(BASE58_STYLE_ABBREVIATE),
			onClose = onClose,
		)
		SignerDivider(sidePadding = 24.dp)
		Column(
			modifier = Modifier
				.verticalScroll(rememberScrollState()),
		) {
			// phrase
			BottomSheetSubtitle(
				R.string.subtitle_secret_recovery_phrase,
				Modifier.padding(top = 14.dp, bottom = 8.dp)
			)
			SeedPhraseBox(seedPhrase)
			//derived keys
			BottomSheetSubtitle(
				R.string.subtitle_derived_keys,
				Modifier.padding(top = 8.dp, bottom = 14.dp)
			)
			for (index in 0..model.derivations.lastIndex) {
				SlimKeyItem(model = model.derivations[index])
				if (index != model.derivations.lastIndex) {
					SignerDivider(sidePadding = 24.dp)
				}
			}
			Spacer(modifier = Modifier.size(height = timerSize.value, width = 1.dp))
		}
	}

	LaunchedEffect(model.seedName) {
		val phrase = getSeedPhraseForBackup(model.seedName)
		if (phrase != null) {
			seedPhrase = phrase
		}
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
private fun PreviewKeySetBackupBottomSheet() {
	val model = KeySetDetailsModel.createStub().toSeedBackupModel()!!
	SignerNewTheme {
		KeySetBackupBottomSheet(model,
			mutableStateOf(80.dp),
			{ _ -> " some long words some some" }, {})
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
private fun PreviewKeySetBackupFullOverlayScreen() {
	val model = KeySetDetailsModel.createStub().toSeedBackupModel()!!
	SignerNewTheme {
		Box(modifier = Modifier.size(350.dp, 700.dp)) {
			KeySetBackupFullOverlayBottomSheet(model,
				{ _ -> " some long words some some" }, {})
		}
	}
}
