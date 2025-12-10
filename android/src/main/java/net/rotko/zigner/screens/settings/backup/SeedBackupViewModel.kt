package net.rotko.zigner.screens.settings.backup

import androidx.lifecycle.ViewModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.storage.mapError


internal class SeedBackupViewModel() : ViewModel() {

	private val seedStorage = ServiceLocator.seedStorage
	private val seedRepository = ServiceLocator.activityScope!!.seedRepository

	fun getSeeds(): List<String> {
		return seedStorage.getSeedNames().toList()
	}

	suspend fun getSeedPhrase(seedName: String): String? {
		return seedRepository.getSeedPhraseForceAuth(seedName).mapError()
	}
}
