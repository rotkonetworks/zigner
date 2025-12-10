package net.rotko.zigner.screens.error.wrongversion

import androidx.lifecycle.ViewModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.storage.RepoResult


class FallbackRecoverPhraseViewModel: ViewModel() {

	private val seedStorage = ServiceLocator.seedStorage
	private val seedRepository = ServiceLocator.activityScope!!.seedRepository


	fun getSeedsList(): List<String> {
		return seedStorage.lastKnownSeedNames.value.toList()
	}

	suspend fun getSeedPhrase(seedName: String): RepoResult<String> {
		return seedRepository.getSeedPhraseForceAuth(seedName)
	}
}
