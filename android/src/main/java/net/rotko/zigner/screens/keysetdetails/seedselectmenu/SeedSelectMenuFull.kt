package net.rotko.zigner.screens.keysetdetails.seedselectmenu

import androidx.compose.runtime.Composable
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.screens.error.handleErrorAppState
import net.rotko.zigner.ui.BottomSheetWrapperRoot
import net.rotko.zigner.ui.mainnavigation.CoreUnlockedNavSubgraph


@Composable
fun SeedSelectMenuFull(
	coreNavController: NavController,
	selectedSeed: String,
	onSelectSeed: (String) -> Unit,
	onClose: Callback,
) {
	val vm: SeedSelectViewModel = viewModel()
	val model = vm.keySetModel.collectAsStateWithLifecycle()

	val modelValue = model.value.handleErrorAppState(coreNavController) ?: return


	BottomSheetWrapperRoot(onClosedAction = onClose) {
		SeedSelectMenuView(
			keySetsListModel = modelValue,
			selectedSeed = selectedSeed,
			onSelectSeed = onSelectSeed,
			onNewKeySet = {
				onClose()
				coreNavController.navigate(
					CoreUnlockedNavSubgraph.newKeySet
				)
			},
			onRecoverKeySet = {
				onClose()
				coreNavController.navigate(
					CoreUnlockedNavSubgraph.recoverKeySet
				)
			},
			onClose = onClose
		)
	}
}




