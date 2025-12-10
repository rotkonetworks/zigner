package net.rotko.zigner.screens.settings.verifiercert

import androidx.lifecycle.ViewModel
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

	suspend fun getVerifierCertModel(): UniffiResult<VerifierDetailsModel> {
		return uniffiInteractor.getVerifierDetails()
	}

	suspend fun wipeWithGeneralCertificate(onAfterAction: Callback): OperationResult<Unit, ErrorStateDestinationState> {
		return resetUseCase.wipeNoGeneralCertWithAuth(onAfterAction)
	}
}
