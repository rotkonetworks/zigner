package net.rotko.zigner.domain.usecases

import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.backend.AuthOperationResult
import net.rotko.zigner.domain.backend.UniffiResult
import net.rotko.zigner.domain.storage.RepoResult

/**
 * Creates key set
 */
class CreateKeySetUseCase() {

	data class AccountDerivation(
		val path: String,
		val genesisHash: String,
		val encryption: String?
	)

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

	/**
	 * Derive accounts for an existing seed using genesis hash lookups
	 * Used for restoring metadata-only backups (v2 format without seed phrase)
	 */
	suspend fun deriveAccountsForExistingSeed(
		seedName: String,
		accounts: List<AccountDerivation>
	): AuthOperationResult {
		val repository = ServiceLocator.activityScope!!.seedRepository
		val uniffiInteractor = ServiceLocator.uniffiInteractor

		// Get the seed phrase for the existing seed
		val seedPhraseResult = repository.getSeedPhraseForceAuth(seedName)
		val seedPhrase = when (seedPhraseResult) {
			is RepoResult.Success -> seedPhraseResult.result
			is RepoResult.Failure -> return AuthOperationResult.Error(
				Exception("Failed to get seed phrase: ${seedPhraseResult.error.message}")
			)
		}

		// Derive each account by genesis hash
		for (account in accounts) {
			val result = uniffiInteractor.tryCreateAddressByGenesis(
				seedName = seedName,
				seedPhrase = seedPhrase,
				path = account.path,
				genesisHashHex = account.genesisHash
			)
			when (result) {
				is UniffiResult.Success -> { /* continue */ }
				is UniffiResult.Error -> {
					// Log but continue - some networks might not be available on target device
					android.util.Log.w("CreateKeySetUseCase",
						"Failed to derive ${account.path}: ${result.error.message}")
				}
			}
		}

		return AuthOperationResult.Success
	}
}
