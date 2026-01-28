package net.rotko.zigner.screens.scan.backuprestore

import android.content.res.Configuration
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.rotko.zigner.R
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.ScreenHeader
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.SignerNewTheme
import net.rotko.zigner.ui.theme.SignerTypeface

@Composable
fun BackupRestoreScreen(
	viewModel: BackupRestoreViewModel,
	modifier: Modifier = Modifier,
	onClose: Callback,
	onRestore: Callback,
) {
	val backupData = viewModel.backupData.collectAsStateWithLifecycle()
	val seedName = viewModel.seedName.collectAsStateWithLifecycle()
	val seedExists = viewModel.seedExists.collectAsStateWithLifecycle()
	val isLoading = viewModel.isLoading.collectAsStateWithLifecycle()

	Column(
		modifier = modifier
			.fillMaxSize()
			.background(MaterialTheme.colors.background)
	) {
		ScreenHeader(
			title = stringResource(R.string.backup_restore_title),
			onBack = onClose,
		)

		Column(
			modifier = Modifier
				.weight(1f)
				.verticalScroll(rememberScrollState())
				.padding(horizontal = 16.dp)
		) {
			Spacer(modifier = Modifier.height(24.dp))

			Text(
				text = stringResource(R.string.backup_restore_description),
				style = SignerTypeface.BodyL,
				color = MaterialTheme.colors.primary,
			)

			Spacer(modifier = Modifier.height(24.dp))

			// Seed name section
			Text(
				text = stringResource(R.string.backup_restore_seed_name_label),
				style = SignerTypeface.TitleS,
				color = MaterialTheme.colors.primary,
			)

			Spacer(modifier = Modifier.height(8.dp))

			Text(
				text = seedName.value,
				style = SignerTypeface.BodyL,
				color = MaterialTheme.colors.primary,
			)

			if (seedExists.value) {
				Spacer(modifier = Modifier.height(4.dp))
				Text(
					text = stringResource(R.string.backup_restore_seed_found),
					style = SignerTypeface.CaptionM,
					color = MaterialTheme.colors.secondary,
				)
			}

			Spacer(modifier = Modifier.height(24.dp))
			SignerDivider()
			Spacer(modifier = Modifier.height(24.dp))

			// Accounts section
			backupData.value?.let { data ->
				if (data.accounts.isNotEmpty()) {
					Text(
						text = stringResource(R.string.backup_restore_accounts_label, data.accounts.size),
						style = SignerTypeface.TitleS,
						color = MaterialTheme.colors.primary,
					)

					Spacer(modifier = Modifier.height(12.dp))

					data.accounts.forEach { account ->
						Column {
							Text(
								text = account.path,
								style = SignerTypeface.BodyM,
								color = MaterialTheme.colors.primary,
							)
							account.networkName?.let { network ->
								Text(
									text = network,
									style = SignerTypeface.CaptionM,
									color = MaterialTheme.colors.secondary,
								)
							}
							Spacer(modifier = Modifier.height(8.dp))
						}
					}
				} else {
					Text(
						text = stringResource(R.string.backup_restore_no_accounts),
						style = SignerTypeface.BodyL,
						color = MaterialTheme.colors.secondary,
					)
				}
			}

			Spacer(modifier = Modifier.height(24.dp))
		}

		// Bottom buttons
		Column(
			modifier = Modifier
				.padding(horizontal = 24.dp)
				.padding(bottom = 24.dp)
		) {
			PrimaryButtonWide(
				label = stringResource(R.string.backup_restore_button),
				isEnabled = seedExists.value && !isLoading.value,
				modifier = Modifier.fillMaxWidth(),
				onClicked = onRestore,
			)

			Spacer(modifier = Modifier.height(12.dp))

			SecondaryButtonWide(
				label = stringResource(R.string.generic_cancel),
				modifier = Modifier.fillMaxWidth(),
				onClicked = onClose,
			)
		}
	}
}

@Composable
fun BackupRestoreLoadingScreen(
	modifier: Modifier = Modifier
) {
	Box(
		modifier = modifier
			.fillMaxSize()
			.background(MaterialTheme.colors.background),
		contentAlignment = Alignment.Center
	) {
		Column(
			horizontalAlignment = Alignment.CenterHorizontally
		) {
			Text(
				text = stringResource(R.string.backup_restore_loading),
				style = SignerTypeface.TitleL,
				color = MaterialTheme.colors.primary,
			)
		}
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
private fun PreviewBackupRestoreLoadingScreen() {
	SignerNewTheme {
		BackupRestoreLoadingScreen()
	}
}
