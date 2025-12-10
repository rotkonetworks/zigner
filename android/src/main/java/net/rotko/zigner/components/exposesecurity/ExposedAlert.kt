package net.rotko.zigner.components.exposesecurity

import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import net.rotko.zigner.components.AlertComponent
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.NetworkState
import net.rotko.zigner.ui.BottomSheetWrapperRoot
import net.rotko.zigner.ui.theme.SignerNewTheme

@Composable
fun ExposedAlert(
	navigateBack: Callback,
	) {

	val vm = viewModel<ExposedViewModel>()
	val networkState: State<NetworkState?> =
		vm.networkState.collectAsStateWithLifecycle()

	when (networkState.value) {
		NetworkState.Active -> {
			SignerNewTheme() {
				BottomSheetWrapperRoot(onClosedAction = navigateBack) {
					ExposedNowBottomSheet(close = navigateBack)
				}
			}
		}

		NetworkState.Past -> {
			SignerNewTheme() {
				BottomSheetWrapperRoot(onClosedAction = navigateBack) {
					ExposedPastBottomSheet(
						close = navigateBack,
						acknowledgeWarning = { vm.acknowledgeWarning() }
					)
				}
			}
		}

		NetworkState.None -> AlertComponent(
			show = true,
			header = "Signer is secure",
			back = navigateBack,
			forward = { },
			backText = "Ok",
			showForward = false
		)

		else -> {
			AlertComponent(
				show = true,
				header = "Network detector failure",
				text = "Please report this error",
				back = navigateBack,
				forward = { },
				backText = "Dismiss",
				showForward = false
			)
		}
	}
}
