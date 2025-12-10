package net.rotko.zigner.components.exposesecurity

import androidx.lifecycle.ViewModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.NetworkState
import kotlinx.coroutines.flow.StateFlow


class ExposedViewModel: ViewModel() {
	private val networkExposedStateKeeper =
		ServiceLocator.networkExposedStateKeeper

	val networkState: StateFlow<NetworkState> =
		networkExposedStateKeeper.airGapModeState

	fun acknowledgeWarning() {
		networkExposedStateKeeper.acknowledgeWarning()
	}
}
