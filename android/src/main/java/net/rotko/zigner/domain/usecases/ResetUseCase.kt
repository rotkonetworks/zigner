package net.rotko.zigner.domain.usecases

import android.widget.Toast
import androidx.fragment.app.FragmentActivity
import net.rotko.zigner.R
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.AuthResult
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.backend.OperationResult
import net.rotko.zigner.domain.getDbNameFromContext
import net.rotko.zigner.domain.isDbCreatedAndOnboardingPassed
import net.rotko.zigner.domain.storage.DatabaseAssetsInteractor
import net.rotko.zigner.screens.error.ErrorStateDestinationState
import io.parity.signer.uniffi.historyInitHistoryNoCert
import io.parity.signer.uniffi.historyInitHistoryWithCert
import io.parity.signer.uniffi.initNavigation


class ResetUseCase {

	private val seedStorage = ServiceLocator.seedStorage
	private val clearCryptedStorage = ServiceLocator.clearCryptedStorage
	private val databaseAssetsInteractor: DatabaseAssetsInteractor =
		ServiceLocator.databaseAssetsInteractor
	private val appContext = ServiceLocator.appContext
	private val networkExposedStateKeeper =
		ServiceLocator.networkExposedStateKeeper
	private val activity: FragmentActivity
		get() = ServiceLocator.activityScope!!.activity

	suspend fun wipeToFactoryWithAuth(onAfterWipe: Callback): OperationResult<Unit, ErrorStateDestinationState> {
		val authentication = ServiceLocator.authentication
		return when (authentication.authenticate(activity)) {
			AuthResult.AuthError,
			AuthResult.AuthFailed ,
			AuthResult.AuthUnavailable -> {
				Toast.makeText(
					activity.baseContext,
					activity.baseContext.getString(R.string.auth_failed_message),
					Toast.LENGTH_SHORT
				).show()
				OperationResult.Ok(Unit)
			}
			AuthResult.AuthSuccess -> {
				databaseAssetsInteractor.wipe()
				val result = totalRefresh()
				onAfterWipe()
				return result
			}
		}
	}

	/**
	 * Auth user and wipe Vault to state without general verifier certificate
	 */
	suspend fun wipeNoGeneralCertWithAuth(onAfterWide: Callback): OperationResult<Unit, ErrorStateDestinationState> {
		val authentication = ServiceLocator.authentication
		return when (authentication.authenticate(activity)) {
			AuthResult.AuthError,
			AuthResult.AuthFailed,
			AuthResult.AuthUnavailable -> {
				Toast.makeText(
					activity.baseContext,
					activity.baseContext.getString(R.string.auth_failed_message),
					Toast.LENGTH_SHORT
				).show()
				OperationResult.Ok(Unit)
			}
			AuthResult.AuthSuccess -> {
				databaseAssetsInteractor.wipe()
				databaseAssetsInteractor.copyAsset("")
				val result = totalRefresh()
				historyInitHistoryNoCert()
				onAfterWide()
				return result
			}
		}
	}

	private fun totalRefreshDbExist() {
		val allNames = seedStorage.getSeedNames()
		initNavigation(appContext.getDbNameFromContext(), allNames.toList())
		ServiceLocator.uniffiInteractor.wasRustInitialized.value = true
		networkExposedStateKeeper.updateAlertStateFromHistory()
	}

	/**
	 * Populate database!
	 * This is first start of the app
	 */
	private fun initAssetsAndTotalRefresh() {
		databaseAssetsInteractor.wipe()
		databaseAssetsInteractor.copyAsset("")
		totalRefreshDbExist()
		historyInitHistoryWithCert()
	}

	/**
	 * This returns the app into starting state;
	 * Do not forget to reset navigation UI state!
	 */
	fun totalRefresh(): OperationResult<Unit, ErrorStateDestinationState> {
		if (!seedStorage.isInitialized()) {
			val result = seedStorage.init(appContext)
			if (result is OperationResult.Err) {
				return result
			}
			val result2 = clearCryptedStorage.init(appContext)
			if (result2 is OperationResult.Err) {
				return result2
			}
		}
		if (!appContext.isDbCreatedAndOnboardingPassed()) {
			initAssetsAndTotalRefresh()
		} else {
			totalRefreshDbExist()
		}
		return OperationResult.Ok(Unit)
	}
}
