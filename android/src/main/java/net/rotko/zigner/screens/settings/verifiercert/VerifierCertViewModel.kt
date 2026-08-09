package net.rotko.zigner.screens.settings.verifiercert

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.VerifierDetailsModel
import net.rotko.zigner.domain.backend.OperationResult
import net.rotko.zigner.domain.backend.UniffiResult
import net.rotko.zigner.domain.usecases.ResetUseCase
import net.rotko.zigner.screens.error.ErrorStateDestinationState


class VerifierCertViewModel: ViewModel() {
	private val resetUseCase = ResetUseCase()
	private val uniffiInteractor = ServiceLocator.uniffiInteractor
	private val preferencesRepository = ServiceLocator.preferencesRepository

	suspend fun getVerifierCertModel(): UniffiResult<VerifierDetailsModel> {
		return uniffiInteractor.getVerifierDetails()
	}

	/**
	 * Whether developer options have already been revealed. Used to short-circuit
	 * the 5-tap gesture once unlocked.
	 */
	val developerOptionsRevealed: StateFlow<Boolean> =
		preferencesRepository.developerOptionsRevealed
			.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), false)

	/**
	 * Reveal the hidden developer options (which surface the online mode toggle in
	 * Advanced Settings). Triggered by the 5-tap gesture on the verifier certificate
	 * value. This only REVEALS the option; it never enables online mode.
	 */
	fun revealDeveloperOptions() {
		viewModelScope.launch {
			preferencesRepository.setDeveloperOptionsRevealed(true)
		}
	}

	suspend fun wipeWithGeneralCertificate(onAfterAction: Callback): OperationResult<Unit, ErrorStateDestinationState> {
		return resetUseCase.wipeNoGeneralCertWithAuth(onAfterAction)
	}
}
