package net.rotko.zigner.ui.rootnavigation

import android.os.Build
import timber.log.Timber
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.captionBarPadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import net.rotko.zigner.domain.MainFlowViewModel
import net.rotko.zigner.domain.NetworkState
import net.rotko.zigner.domain.addVaultLogger
import net.rotko.zigner.screens.error.handleErrorAppState
import net.rotko.zigner.screens.initial.UnlockAppAuthScreen
import net.rotko.zigner.screens.initial.UnlockingScreen
import net.rotko.zigner.ui.mainnavigation.CoreUnlockedNavSubgraph
import kotlinx.coroutines.launch


fun NavGraphBuilder.mainSignerAppFlow(globalNavController: NavHostController) {
	composable(route = MainGraphRoutes.mainScreenRoute) {
		val mainFlowViewModel: MainFlowViewModel = viewModel()

		val authenticated =
			mainFlowViewModel.authenticated.collectAsStateWithLifecycle()

		val isUnlocking =
			mainFlowViewModel.isUnlocking.collectAsStateWithLifecycle()

		val unlockStatus =
			mainFlowViewModel.unlockStatus.collectAsStateWithLifecycle()

		val unlockedNavController =
			rememberNavController().apply { addVaultLogger() }

		val networkState =
			mainFlowViewModel.networkState.collectAsStateWithLifecycle()

		when {
			authenticated.value -> {
				// Structure to contain all app
				Box(
					modifier = Modifier
						.navigationBarsPadding()
						.captionBarPadding(),
				) {
					CoreUnlockedNavSubgraph(unlockedNavController)
				}

				//check for network and navigate to blocker screen if needed
				when (networkState.value) {
					NetworkState.Active -> {
						if (unlockedNavController.currentDestination
								?.route != CoreUnlockedNavSubgraph.airgapBreached
						) {
							unlockedNavController.navigate(CoreUnlockedNavSubgraph.airgapBreached)
						}
					}
					else -> {}
				}
			}
			isUnlocking.value -> {
				UnlockingScreen(status = unlockStatus.value)
			}
			else -> {
				UnlockAppAuthScreen(onUnlockClicked = {
					mainFlowViewModel.viewModelScope.launch {
						mainFlowViewModel.onUnlockClicked()
							.handleErrorAppState(globalNavController)
					}
				})
			}
		}
	}
}



