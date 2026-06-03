package net.rotko.zigner.screens.settings.general

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import net.rotko.zigner.components.exposesecurity.ExposedAlert
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.screens.error.handleErrorAppState
import net.rotko.zigner.screens.settings.SettingsNavSubgraph
import net.rotko.zigner.ui.BottomSheetWrapperRoot
import net.rotko.zigner.ui.mainnavigation.CoreUnlockedNavSubgraph
import kotlinx.coroutines.launch


@Composable
internal fun SettingsGeneralNavSubgraph(
	coreNavController: NavController,
) {
	val context = LocalContext.current
	val vm: SettingsGeneralViewModel = viewModel()

	val appVersion = rememberSaveable { vm.getAppVersion(context) }
	val shieldState = vm.networkState.collectAsStateWithLifecycle()
	val onlineModeEnabled = vm.onlineModeEnabled.collectAsStateWithLifecycle()
	val onlineModeWasEverEnabled = vm.onlineModeWasEverEnabled.collectAsStateWithLifecycle()
	val lightThemeEnabled = vm.lightThemeEnabled.collectAsStateWithLifecycle()

	val menuNavController = rememberNavController()

	val securitySummary = rememberSaveable { vm.getSecuritySummary(context) }

	Box(modifier = Modifier.statusBarsPadding()) {
		SettingsScreenGeneralView(
			navController = coreNavController,
			onWipeData = { menuNavController.navigate(SettingsGeneralMenu.wipe_factory) },
			onOpenLogs = { coreNavController.navigate(SettingsNavSubgraph.logs) },
			onShowTerms = { coreNavController.navigate(SettingsNavSubgraph.terms) },
			onShowPrivacyPolicy = {
				coreNavController.navigate(SettingsNavSubgraph.privacyPolicy)
			},
			onBackup = { coreNavController.navigate(SettingsNavSubgraph.backup) },
			onMultisigSettings = { coreNavController.navigate(SettingsNavSubgraph.multisig) },
			onManageNetworks = {
				coreNavController.navigate(SettingsNavSubgraph.networkList)
			},
			onGeneralVerifier = {
				coreNavController.navigate(SettingsNavSubgraph.generalVerifier)
			},
			onExposedClicked = { menuNavController.navigate(SettingsGeneralMenu.exposed_shield_alert) },
			onZcashTestQr = { },
			onOnlineModeToggle = {
				if (onlineModeEnabled.value) {
					// Switching back to offline - still requires confirmation
					menuNavController.navigate(SettingsGeneralMenu.offline_mode_confirm)
				} else {
					// Show confirmation for enabling online mode
					menuNavController.navigate(SettingsGeneralMenu.online_mode_confirm)
				}
			},
			onLightThemeToggle = { vm.toggleLightTheme() },
			isStrongBoxProtected = vm.isStrongBoxProtected,
			isOnlineModeEnabled = onlineModeEnabled.value,
			wasOnlineModeEverEnabled = onlineModeWasEverEnabled.value,
			isLightThemeEnabled = lightThemeEnabled.value,
			securitySummary = securitySummary,
			appVersion = appVersion,
			networkState = shieldState,
		)
	}

	NavHost(
		navController = menuNavController,
		startDestination = SettingsGeneralMenu.empty,
	) {
		val closeAction: Callback = {
			menuNavController.popBackStack()
		}
		composable(SettingsGeneralMenu.empty) {
			//no menu - Spacer element so when other part shown there won't
			// be an appearance animation from top left part despite there shouldn't be
			Spacer(modifier = Modifier.fillMaxSize(1f))
		}
		composable(SettingsGeneralMenu.wipe_factory) {
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
		composable(SettingsGeneralMenu.exposed_shield_alert) {
			ExposedAlert(navigateBack = closeAction)
		}
		composable(SettingsGeneralMenu.online_mode_confirm) {
			BottomSheetWrapperRoot(onClosedAction = closeAction) {
				// Use different dialog for first-time vs re-enabling
				if (onlineModeWasEverEnabled.value) {
					// User has used online mode before - show timed confirmation
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
					// First time - show full warning about permanent flag
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
		composable(SettingsGeneralMenu.offline_mode_confirm) {
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


private object SettingsGeneralMenu {
	const val empty = "settings_menu_empty"
	const val wipe_factory = "settings_confirm_reset"
	const val exposed_shield_alert = "settings_exposed"
	const val online_mode_confirm = "settings_online_mode_confirm"
	const val offline_mode_confirm = "settings_offline_mode_confirm"
}
