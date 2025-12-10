package net.rotko.zigner.screens.scan.bananasplitcreate.show

import androidx.lifecycle.ViewModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.backend.OperationResult
import net.rotko.zigner.domain.backend.UniffiInteractor
import io.parity.signer.uniffi.ErrorDisplayed
import io.parity.signer.uniffi.QrData
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext


class ShowBananaSplitViewModel : ViewModel() {
	private val bsRepository = ServiceLocator.activityScope!!.bsRepository


	fun getBananaSplitQrs(seedName: String): List<QrData>? {
		return bsRepository.getBsQrs(seedName)
	}

	suspend fun removeBS(seedName: String): OperationResult<Unit, ErrorDisplayed> {
		return bsRepository.removeBS(seedName)

	}

	suspend fun getPassword(seedName: String): OperationResult<String, ErrorDisplayed> {
		return bsRepository.getBsPassword(seedName)
	}
}
