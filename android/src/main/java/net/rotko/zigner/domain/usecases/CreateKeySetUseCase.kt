package net.rotko.zigner.domain.usecases

import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.backend.AuthOperationResult

/**
 * Creates key set
 */
class CreateKeySetUseCase() {

	suspend fun createKeySetWithNetworks(
		seedName: String,
		seedPhrase: String,
		networksKeys: List<String>,
	): AuthOperationResult {
		val repository = ServiceLocator.activityScope!!.seedRepository
		return repository.addSeed(
			seedName = seedName,
			seedPhrase = seedPhrase,
			networksKeys = networksKeys,
		)
	}
}
