package net.rotko.zigner.screens.settings.networks.list

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.compose.composable
import net.rotko.zigner.domain.backend.mapError
import net.rotko.zigner.screens.error.handleErrorAppState
import net.rotko.zigner.screens.settings.SettingsNavSubgraph
import net.rotko.zigner.ui.mainnavigation.CoreUnlockedNavSubgraph
import kotlinx.coroutines.runBlocking


fun NavGraphBuilder.networkListDestination(
	navController: NavController,
) {
	composable(SettingsNavSubgraph.networkList) {
		val vm: NetworkListViewModel = viewModel()

		val model = remember {
			runBlocking {
				vm.getNetworkList()
			}.handleErrorAppState(navController)
		} ?: return@composable

		Box(modifier = Modifier.statusBarsPadding()) {
			NetworksListScreen(
				model = model,
				onBack = navController::popBackStack,
				onOpenNetwork = { networkKey ->
					navController.navigate(
						SettingsNavSubgraph.NetworkDetails.destination(networkKey)
					)
				},
				onNetworkHelp = { navController.navigate(CoreUnlockedNavSubgraph.networkHelpers) },
				onAddNetwork = { navController.navigate(CoreUnlockedNavSubgraph.Camera.destination(null)) },
			)
		}
	}
}
