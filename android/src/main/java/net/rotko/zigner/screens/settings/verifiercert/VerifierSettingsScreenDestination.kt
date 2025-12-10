package net.rotko.zigner.screens.settings.verifiercert

import androidx.compose.runtime.remember
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import net.rotko.zigner.screens.error.handleErrorAppState
import net.rotko.zigner.screens.settings.SettingsNavSubgraph
import net.rotko.zigner.ui.mainnavigation.CoreUnlockedNavSubgraph
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking


fun NavGraphBuilder.verifierSettingsDestination(
	coreNavController: NavController,
) {
	composable(SettingsNavSubgraph.generalVerifier) {
		val vm: VerifierCertViewModel = viewModel()

		val model = remember {
			runBlocking {
				vm.getVerifierCertModel()
			}.handleErrorAppState(coreNavController)
		} ?: return@composable

		VerifierScreenFull(
			verifierDetails = model,
			wipe = {
				vm.viewModelScope.launch {
					vm.wipeWithGeneralCertificate {
						coreNavController.navigate(
							CoreUnlockedNavSubgraph.KeySet.destination(null)
						)
					}.handleErrorAppState(coreNavController)
				}
			},
			onBack = coreNavController::popBackStack,
		)
	}
}
