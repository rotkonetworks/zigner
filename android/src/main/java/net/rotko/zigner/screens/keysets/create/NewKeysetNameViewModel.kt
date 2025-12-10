package net.rotko.zigner.screens.keysets.create

import androidx.lifecycle.ViewModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.backend.UniffiResult
import kotlinx.coroutines.runBlocking


class NewKeysetNameViewModel : ViewModel() {

	private val uniffi = ServiceLocator.uniffiInteractor

	val seedNames =
		ServiceLocator.seedStorage.lastKnownSeedNames

	fun createNewSeedPhrase(): UniffiResult<String> {
		return runBlocking {
			uniffi.createNewSeedPhrase()
		}
	}
}
