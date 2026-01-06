package net.rotko.zigner.domain

import android.annotation.SuppressLint
import android.content.*
import timber.log.Timber
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.backend.OperationResult
import net.rotko.zigner.domain.usecases.ResetUseCase
import net.rotko.zigner.screens.error.ErrorStateDestinationState
import io.parity.signer.uniffi.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch


@SuppressLint("StaticFieldLeak")
class MainFlowViewModel() : ViewModel() {

	private val resetUseCase = ResetUseCase()
	private val authentication = ServiceLocator.authentication
	private val networkExposedStateKeeper =
		ServiceLocator.networkExposedStateKeeper

	val networkState: StateFlow<NetworkState> =
		networkExposedStateKeeper.airGapModeState

	val activity: FragmentActivity
		get() = ServiceLocator.activityScope!!.activity

	private val _isUnlocking = MutableStateFlow(false)
	val isUnlocking: StateFlow<Boolean> = _isUnlocking.asStateFlow()

	private val _unlockStatus = MutableStateFlow("")
	val unlockStatus: StateFlow<String> = _unlockStatus.asStateFlow()

	suspend fun onUnlockClicked(): OperationResult<Unit, ErrorStateDestinationState> {
		_isUnlocking.value = true
		_unlockStatus.value = "Verifying with secure hardware..."
		return when (authentication.authenticate(activity)) {
			AuthResult.AuthSuccess -> {
				val result = resetUseCase.totalRefresh { status ->
					_unlockStatus.value = status
				}
				_unlockStatus.value = ""
				_isUnlocking.value = false
				result
			}
			AuthResult.AuthError,
			AuthResult.AuthFailed,
			AuthResult.AuthUnavailable -> {
				Timber.e("Signer", "Auth failed, not unlocked")
				_unlockStatus.value = ""
				_isUnlocking.value = false
				OperationResult.Ok(Unit)
			}
		}
	}

	val authenticated: StateFlow<Boolean> = authentication.auth
}

