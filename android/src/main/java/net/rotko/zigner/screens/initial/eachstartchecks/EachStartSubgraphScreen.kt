package net.rotko.zigner.screens.initial.eachstartchecks

import android.content.Context
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.captionBarPadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import kotlinx.coroutines.launch
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.NetworkState
import net.rotko.zigner.domain.isDbCreatedAndOnboardingPassed
import net.rotko.zigner.screens.initial.eachstartchecks.airgap.AirgapScreen
import net.rotko.zigner.screens.initial.eachstartchecks.osversion.OutdatedOsVersionScreen
import net.rotko.zigner.screens.initial.eachstartchecks.rootcheck.DeviceIntegrityScreen
import net.rotko.zigner.screens.initial.eachstartchecks.screenlock.SetScreenLockScreen
import net.rotko.zigner.screens.settings.general.ConfirmOnlineModeBottomSheet
import net.rotko.zigner.ui.BottomSheetWrapperRoot
import net.rotko.zigner.ui.rootnavigation.MainGraphRoutes


fun NavGraphBuilder.enableEachStartAppFlow(globalNavController: NavHostController) {
	composable(route = MainGraphRoutes.eachTimeOnboardingRoute) {
		val viewModel: EachStartViewModel = viewModel()
		val context: Context = LocalContext.current

		val goToNextFlow: Callback = {
			globalNavController.navigate(MainGraphRoutes.mainScreenRoute) {
				popUpTo(0)
			}
		}

		val integrity = remember { viewModel.deviceIntegrity() }

		// The checks after the integrity notice; null means none apply.
		fun stepAfterIntegrity(): EachStartSubgraphScreenSteps? =
			if (!viewModel.isAuthPossible(context)) {
				EachStartSubgraphScreenSteps.SET_SCREEN_LOCK_BLOCKER
			} else if (viewModel.networkState.value == NetworkState.Active || !context.isDbCreatedAndOnboardingPassed()) {
				EachStartSubgraphScreenSteps.AIR_GAP
			} else {
				null
			}

		// Checked every start, not only at install: patch age grows monthly,
		// so a phone current at install can be a year behind later.
		val stalePatch = remember { viewModel.stalePatch() }

		fun stepAfterPatch(): EachStartSubgraphScreenSteps? =
			if (integrity.needsAttention) {
				EachStartSubgraphScreenSteps.DEVICE_INTEGRITY
			} else {
				stepAfterIntegrity()
			}

		val state = remember {
			mutableStateOf(
				if (stalePatch != null) {
					EachStartSubgraphScreenSteps.STALE_PATCH
				} else {
					stepAfterPatch() ?: goToNextFlow()
				}
			)
		}

		Box(modifier = Modifier
				.navigationBarsPadding()
				.captionBarPadding()
				.statusBarsPadding()
		) {
			when (state.value) {
				EachStartSubgraphScreenSteps.STALE_PATCH -> {
					OutdatedOsVersionScreen(
						status = stalePatch!!,
						onProceed = {
							state.value = stepAfterPatch() ?: goToNextFlow()
						},
					)
				}
				EachStartSubgraphScreenSteps.DEVICE_INTEGRITY -> {
					DeviceIntegrityScreen(
						report = integrity,
						onProceed = {
							state.value = stepAfterIntegrity() ?: goToNextFlow()
						},
					)
				}
				EachStartSubgraphScreenSteps.SET_SCREEN_LOCK_BLOCKER -> {
					//first show enable screen lock if needed
					val lifecycleOwner: LifecycleOwner = LocalLifecycleOwner.current
					DisposableEffect(this) {
						val observer = LifecycleEventObserver { _, event ->
							if (event.targetState == Lifecycle.State.RESUMED) {
								if (viewModel.isAuthPossible(context)) {
									state.value = EachStartSubgraphScreenSteps.AIR_GAP
								}
							}
						}
						lifecycleOwner.lifecycle.addObserver(observer)
						onDispose {
							lifecycleOwner.lifecycle.removeObserver(observer)
						}
					}
					SetScreenLockScreen()
				}
				EachStartSubgraphScreenSteps.AIR_GAP -> {
					val showOnlineModeConfirm = remember { mutableStateOf(false) }
					val coroutineScope = rememberCoroutineScope()

					AirgapScreen(
						isInitialOnboarding = true,
						onProceed = {
							//go to next screen
							goToNextFlow()
						},
						onEnableOnlineMode = {
							showOnlineModeConfirm.value = true
						}
					)

					if (showOnlineModeConfirm.value) {
						BottomSheetWrapperRoot(
							onClosedAction = { showOnlineModeConfirm.value = false }
						) {
							ConfirmOnlineModeBottomSheet(
								onCancel = { showOnlineModeConfirm.value = false },
								onConfirm = {
									coroutineScope.launch {
										viewModel.enableOnlineMode()
										showOnlineModeConfirm.value = false
										goToNextFlow()
									}
								}
							)
						}
					}
				}
			}
		}
	}
}

private enum class EachStartSubgraphScreenSteps { STALE_PATCH, DEVICE_INTEGRITY, AIR_GAP, SET_SCREEN_LOCK_BLOCKER }
