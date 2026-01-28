package net.rotko.zigner.screens.scan.backuprestore

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import net.rotko.zigner.domain.Callback
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.launch

@Composable
fun BackupRestoreSubgraph(
	urFrames: List<String>,
	onClose: Callback,
	onSuccess: (seedName: String) -> Unit,
	onError: (errorText: String) -> Unit,
) {
	val viewModel: BackupRestoreViewModel = viewModel()
	val context = LocalContext.current

	DisposableEffect(urFrames) {
		viewModel.initWithUrFrames(urFrames, context)
		onDispose {
			viewModel.cleanState()
		}
	}

	LaunchedEffect(key1 = urFrames) {
		launch {
			viewModel.isSuccessTerminal
				.filterNotNull()
				.collect { seedName ->
					onSuccess(seedName)
				}
		}
		launch {
			viewModel.isErrorTerminal
				.filterNotNull()
				.collect { error ->
					onError(error)
				}
		}
	}

	val backupData = viewModel.backupData.collectAsStateWithLifecycle()
	val isLoading = viewModel.isLoading.collectAsStateWithLifecycle()

	BackHandler(onBack = onClose)

	Box(
		modifier = Modifier
			.fillMaxSize(1f)
			.statusBarsPadding()
			.background(MaterialTheme.colors.background)
	)

	if (backupData.value != null) {
		BackupRestoreScreen(
			viewModel = viewModel,
			modifier = Modifier.statusBarsPadding(),
			onClose = onClose,
			onRestore = {
				viewModel.viewModelScope.launch {
					viewModel.restoreBackup(context)
				}
			}
		)
	} else if (isLoading.value) {
		BackupRestoreLoadingScreen(
			modifier = Modifier.statusBarsPadding()
		)
	}
}
