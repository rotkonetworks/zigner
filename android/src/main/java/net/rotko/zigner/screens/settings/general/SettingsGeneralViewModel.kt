package net.rotko.zigner.screens.settings.general

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.NetworkState
import net.rotko.zigner.domain.backend.OperationResult
import net.rotko.zigner.domain.usecases.ResetUseCase
import net.rotko.zigner.screens.error.ErrorStateDestinationState
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch


class SettingsGeneralViewModel: ViewModel() {

	private val resetUseCase: ResetUseCase = ResetUseCase()
	private val preferencesRepository = ServiceLocator.preferencesRepository

	val isStrongBoxProtected: Boolean = ServiceLocator.seedStorage.isStrongBoxProtected

	fun getAppVersion(context: Context): String {
		return context.packageManager.getPackageInfo(
			context.packageName,
			0
		).versionName
	}

	val networkState: StateFlow<NetworkState> =
		ServiceLocator.networkExposedStateKeeper.airGapModeState

	/**
	 * Online mode allows using Zigner with network radios enabled.
	 * This is an opt-in feature that bypasses airgap checks.
	 */
	val onlineModeEnabled: StateFlow<Boolean> =
		preferencesRepository.onlineModeEnabled
			.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), false)

	fun setOnlineModeEnabled(enabled: Boolean) {
		viewModelScope.launch {
			preferencesRepository.setOnlineModeEnabled(enabled)
		}
	}

	/**
	 * Auth user and wipe the Vault to initial state
	 */
	suspend fun wipeToFactory(onAfterWipe: Callback): OperationResult<Unit, ErrorStateDestinationState> {
		return resetUseCase.wipeToFactoryWithAuth(onAfterWipe)
	}
}
