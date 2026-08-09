package net.rotko.zigner.screens.settings.verifiercert

import androidx.compose.material.ExperimentalMaterialApi
import androidx.compose.material.ModalBottomSheetValue
import androidx.compose.material.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.VerifierDetailsModel
import net.rotko.zigner.ui.BottomSheetWrapperContent
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterialApi::class)
@Composable
fun VerifierScreenFull(
	verifierDetails: VerifierDetailsModel,
	wipe: Callback,
	onBack: Callback,
	developerOptionsRevealed: Boolean = false,
	onRevealDeveloperOptions: Callback = {},
) {
	val bottomSheetState =
		rememberModalBottomSheetState(
			ModalBottomSheetValue.Hidden,
			skipHalfExpanded = true,
			confirmValueChange = {
				it != ModalBottomSheetValue.HalfExpanded
			}
		)
	val scope = rememberCoroutineScope()

	BottomSheetWrapperContent(
		bottomSheetState = bottomSheetState,
		bottomSheetContent = {
			SettingsWipeAllConfirmation(
				onCancel = { scope.launch { bottomSheetState.hide() } },
				onWipe = wipe,
			)
		},
		mainContent = {
			VerifierScreen(
				verifierDetails = verifierDetails,
				onBack = onBack,
				onRemove = { scope.launch { bottomSheetState.show() } },
				developerOptionsRevealed = developerOptionsRevealed,
				onRevealDeveloperOptions = onRevealDeveloperOptions,
			)
		},
	)
}


