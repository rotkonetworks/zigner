package net.rotko.zigner.screens.settings.general

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import kotlinx.coroutines.launch
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.screens.error.handleErrorAppState
import net.rotko.zigner.screens.settings.SettingsNavSubgraph
import net.rotko.zigner.ui.BottomSheetWrapperRoot
import net.rotko.zigner.ui.mainnavigation.CoreUnlockedNavSubgraph

@Composable
internal fun SettingsAdvancedNavSubgraph(
	coreNavController: NavController,
) {
	// Share the same VM if we can, or just get it again (it's usually singleton or activity-scoped if needed)
	// For simplicity, we just use the same viewModel() call which is usually enough for settings.
	val vm: SettingsGeneralViewModel = viewModel()

	val onlineModeEnabled = vm.onlineModeEnabled.collectAsStateWithLifecycle()
	val onlineModeWasEverEnabled = vm.onlineModeWasEverEnabled.collectAsStateWithLifecycle()
	val developerOptionsRevealed = vm.developerOptionsRevealed.collectAsStateWithLifecycle()

	val menuNavController = rememberNavController()

	Box(modifier = Modifier.statusBarsPadding()) {
		SettingsAdvancedScreen(
			onBack = { coreNavController.popBackStack() },
			onVerifierCertificate = { coreNavController.navigate(SettingsNavSubgraph.generalVerifier) },
			onOnlineModeToggle = {
				if (onlineModeEnabled.value) {
					menuNavController.navigate(SettingsAdvancedMenu.offline_mode_confirm)
				} else {
					menuNavController.navigate(SettingsAdvancedMenu.online_mode_confirm)
				}
			},
			onWipeData = { menuNavController.navigate(SettingsAdvancedMenu.wipe_factory) },
			isOnlineModeEnabled = onlineModeEnabled.value,
			wasOnlineModeEverEnabled = onlineModeWasEverEnabled.value,
			developerOptionsRevealed = developerOptionsRevealed.value,
		)
	}

	NavHost(
		navController = menuNavController,
		startDestination = SettingsAdvancedMenu.empty,
	) {
		val closeAction: Callback = {
			menuNavController.popBackStack()
		}
		composable(SettingsAdvancedMenu.empty) {
			Spacer(modifier = Modifier.fillMaxSize(1f))
		}
		composable(SettingsAdvancedMenu.wipe_factory) {
			BottomSheetWrapperRoot(onClosedAction = closeAction) {
				ConfirmFactorySettingsBottomSheet(
					onCancel = closeAction,
					onFactoryReset = {
						vm.viewModelScope.launch {
							vm.wipeToFactory {
								coreNavController.navigate(
									CoreUnlockedNavSubgraph.KeySet.destination(null)
								)
							}.handleErrorAppState(coreNavController)
						}
					}
				)
			}
		}
		composable(SettingsAdvancedMenu.online_mode_confirm) {
			BottomSheetWrapperRoot(onClosedAction = closeAction) {
				if (onlineModeWasEverEnabled.value) {
					ConfirmReEnableOnlineModeBottomSheet(
						onCancel = closeAction,
						onConfirm = {
							vm.viewModelScope.launch {
								vm.enableOnlineModeWithAuth {
									closeAction()
								}.handleErrorAppState(coreNavController)
							}
						}
					)
				} else {
					ConfirmOnlineModeBottomSheet(
						onCancel = closeAction,
						onConfirm = {
							vm.viewModelScope.launch {
								vm.enableOnlineModeWithAuth {
									closeAction()
								}.handleErrorAppState(coreNavController)
							}
						}
					)
				}
			}
		}
		composable(SettingsAdvancedMenu.offline_mode_confirm) {
			BottomSheetWrapperRoot(onClosedAction = closeAction) {
				ConfirmOfflineModeBottomSheet(
					onCancel = closeAction,
					onConfirm = {
						vm.viewModelScope.launch {
							vm.disableOnlineModeWithAuth {
								closeAction()
							}.handleErrorAppState(coreNavController)
						}
					}
				)
			}
		}
	}
}

private object SettingsAdvancedMenu {
	const val empty = "settings_adv_menu_empty"
	const val wipe_factory = "settings_adv_confirm_reset"
	const val online_mode_confirm = "settings_adv_online_mode_confirm"
	const val offline_mode_confirm = "settings_adv_offline_mode_confirm"
}
