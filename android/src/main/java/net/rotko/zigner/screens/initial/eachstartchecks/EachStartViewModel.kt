package net.rotko.zigner.screens.initial.eachstartchecks

import android.content.Context
import androidx.lifecycle.ViewModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.Authentication
import net.rotko.zigner.domain.NetworkState
import net.rotko.zigner.domain.RootUtils
import kotlinx.coroutines.flow.StateFlow


class EachStartViewModel : ViewModel() {

	private val networkExposedStateKeeper =
		ServiceLocator.networkExposedStateKeeper
	private val preferencesRepository =
		ServiceLocator.preferencesRepository

	fun isAuthPossible(context: Context): Boolean = Authentication.canAuthenticate(context)

	fun isDeviceRooted(): Boolean {
		return RootUtils.isDeviceRooted()
	}

	val networkState: StateFlow<NetworkState> = networkExposedStateKeeper.airGapModeState

	/**
	 * Enable online mode to bypass airgap requirements.
	 * This is called when user chooses to use online mode from the airgap screen.
	 */
	suspend fun enableOnlineMode() {
		preferencesRepository.setOnlineModeEnabled(true)
	}
}
