package net.rotko.zigner.screens.scan.transaction.dynamicderivations

import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.BottomSheetWrapperRoot
import io.parity.signer.uniffi.DdPreview


@Composable
fun AddDynamicDerivationScreenFull(
	model: DdPreview,
	onClose: Callback,
) {

	AddDerivedKeysScreen(
		model = model,
		modifier = Modifier.statusBarsPadding(),
		onBack = onClose,
		onDone = onClose,
	)
}
