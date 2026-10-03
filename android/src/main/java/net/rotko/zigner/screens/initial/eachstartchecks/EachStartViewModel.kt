package net.rotko.zigner.screens.initial.eachstartchecks

import android.content.Context
import androidx.lifecycle.ViewModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.Authentication
import net.rotko.zigner.domain.NetworkState
import net.rotko.zigner.domain.security.DeviceIntegrity
import net.rotko.zigner.domain.security.SecurityPatch
import kotlinx.coroutines.flow.StateFlow


class EachStartViewModel : ViewModel() {

	private val networkExposedStateKeeper =
		ServiceLocator.networkExposedStateKeeper
	private val preferencesRepository =
		ServiceLocator.preferencesRepository

	fun isAuthPossible(context: Context): Boolean = Authentication.canAuthenticate(context)

	fun deviceIntegrity(): DeviceIntegrity.Report = DeviceIntegrity.current()

	/** Non-null when the patch-age warning should be shown. */
	fun stalePatch(): SecurityPatch.Status.Stale? = SecurityPatch.current() as? SecurityPatch.Status.Stale

	val networkState: StateFlow<NetworkState> = networkExposedStateKeeper.airGapModeState

	/**
	 * Enable online mode to bypass airgap requirements.
	 * This is called when user chooses to use online mode from the airgap screen.
	 */
	suspend fun enableOnlineMode() {
		preferencesRepository.setOnlineModeEnabled(true)
	}
}
