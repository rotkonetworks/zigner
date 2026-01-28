package net.rotko.zigner.screens.settings.backupexport

import android.content.res.Configuration
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalInspectionMode
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import net.rotko.zigner.R
import net.rotko.zigner.components.base.NotificationFrameText
import net.rotko.zigner.components.base.ScreenHeaderClose
import net.rotko.zigner.components.qrcode.AnimatedQrKeysInfo
import net.rotko.zigner.components.qrcode.AnimatedQrImages
import net.rotko.zigner.components.qrcode.AnimatedQrKeysProvider
import net.rotko.zigner.components.qrcode.EmptyAnimatedQrKeysProvider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.getData
import net.rotko.zigner.ui.helpers.PreviewData
import net.rotko.zigner.ui.theme.SignerNewTheme
import net.rotko.zigner.ui.theme.SignerTypeface
import io.parity.signer.uniffi.QrData

@Composable
fun BackupExportScreen(
	seedName: String,
	seedPhrase: String,
	onClose: Callback,
	modifier: Modifier = Modifier,
) {
	val viewModel: BackupExportViewModel = viewModel()
	val qrFrames = viewModel.qrFrames.collectAsStateWithLifecycle()
	val isLoading = viewModel.isLoading.collectAsStateWithLifecycle()
	val error = viewModel.error.collectAsStateWithLifecycle()

	LaunchedEffect(seedName, seedPhrase) {
		viewModel.loadBackupQr(seedName, seedPhrase)
	}

	DisposableEffect(Unit) {
		onDispose {
			viewModel.clearState()
		}
	}

	Column(
		modifier = modifier
			.fillMaxSize()
			.background(MaterialTheme.colors.background)
	) {
		ScreenHeaderClose(
			title = stringResource(R.string.backup_export_title),
			onClose = onClose,
		)

		Column(
			modifier = Modifier
				.weight(1f)
				.verticalScroll(rememberScrollState())
				.padding(horizontal = 16.dp)
		) {
			Spacer(modifier = Modifier.height(24.dp))

			when {
				isLoading.value -> {
					Box(
						modifier = Modifier
							.fillMaxWidth()
							.height(300.dp),
						contentAlignment = Alignment.Center
					) {
						Text(
							text = "Generating QR codes...",
							style = SignerTypeface.BodyL,
							color = MaterialTheme.colors.secondary,
						)
					}
				}
				error.value != null -> {
					Box(
						modifier = Modifier
							.fillMaxWidth()
							.height(300.dp),
						contentAlignment = Alignment.Center
					) {
						Text(
							text = error.value ?: "Error",
							style = SignerTypeface.BodyL,
							color = MaterialTheme.colors.error,
						)
					}
				}
				qrFrames.value != null -> {
					if (LocalInspectionMode.current) {
						AnimatedQrKeysInfo(
							input = Unit,
							provider = EmptyAnimatedQrKeysProvider(),
							modifier = Modifier.padding(8.dp)
						)
					} else {
						AnimatedQrKeysInfo(
							input = qrFrames.value!!.map { it.getData() },
							provider = BackupQrProvider(),
							modifier = Modifier.padding(8.dp)
						)
					}
				}
			}

			Spacer(modifier = Modifier.height(24.dp))

			NotificationFrameText(
				message = stringResource(R.string.backup_export_warning)
			)

			Spacer(modifier = Modifier.height(16.dp))

			Text(
				text = stringResource(R.string.backup_export_description),
				style = SignerTypeface.BodyM,
				color = MaterialTheme.colors.secondary,
			)

			Spacer(modifier = Modifier.height(48.dp))
		}
	}
}

class BackupQrProvider : AnimatedQrKeysProvider<List<List<UByte>>> {
	override suspend fun getQrCodesList(input: List<List<UByte>>): AnimatedQrImages {
		return AnimatedQrImages(input)
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
private fun PreviewBackupExportScreen() {
	SignerNewTheme {
		BackupExportScreen(
			seedName = "My Wallet",
			seedPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			onClose = {},
		)
	}
}
