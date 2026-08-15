package net.rotko.zigner.screens.settings.releasekey

import androidx.lifecycle.ViewModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.storage.mapError

// Backs the Release key settings entry: list the seeds, and hand back the
// phrase for the one the operator picks (behind the same biometric auth every
// other seed read goes through). The pubkey derivation itself lives in
// ReleaseKeyScreen - this view model only unlocks the seed to feed it.
internal class ReleaseKeyViewModel : ViewModel() {

	private val seedStorage = ServiceLocator.seedStorage
	private val seedRepository = ServiceLocator.activityScope!!.seedRepository

	fun getSeeds(): List<String> = seedStorage.getSeedNames().toList()

	suspend fun getSeedPhrase(seedName: String): String? =
		seedRepository.getSeedPhraseForceAuth(seedName).mapError()
}
