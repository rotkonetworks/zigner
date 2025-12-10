package net.rotko.zigner.screens.scan.addnetwork

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.NetworkModel
import net.rotko.zigner.domain.storage.RepoResult
import net.rotko.zigner.domain.storage.SeedRepository
import net.rotko.zigner.domain.submitErrorState
import net.rotko.zigner.domain.toNetworkModel
import io.parity.signer.uniffi.ErrorDisplayed
import io.parity.signer.uniffi.getManagedNetworks
import io.parity.signer.uniffi.tryCreateAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext


class AddedNetworkViewModel : ViewModel() {

	private val repository: SeedRepository
		get() = ServiceLocator.activityScope!!.seedRepository

	fun getSeedList(): List<String> {
		return repository.getLastKnownSeedNames().toList()
	}

	suspend fun getNetworkByName(name: String): NetworkModel? {
		return try {
			withContext(viewModelScope.coroutineContext + Dispatchers.IO) {
				getManagedNetworks().networks.firstOrNull { it.title.lowercase() == name.lowercase() }
					?.toNetworkModel()
			}
		} catch (e: Exception) {
			submitErrorState("cannot find new network to suggest adding keys, unexpected case!")
			null
		}
	}

	fun processAddNetworkToSeeds(
		network: NetworkModel,
		seeds: List<String>,
		onAfterProcess: (Boolean) -> Unit,
	) {
		viewModelScope.launch {
			var result = true
			val seedPairs = repository.fillSeedToPhrasesAuth(seeds)
			when (seedPairs) {
				is RepoResult.Failure -> {
					result = false
					submitErrorState("failed to add network to seeds with error ${seedPairs.error}")
				}

				is RepoResult.Success -> seedPairs.result.forEach { seedPair ->
					try {
						tryCreateAddress(
							seedName = seedPair.first, seedPhrase = seedPair.second,
							path = network.pathId, network = network.key,
						)
						System.gc()
					} catch (e: ErrorDisplayed) {
						result = false
						submitErrorState("can't create network key for added network, ${e.message}")
					}
				}
			}
			onAfterProcess(result)
		}
	}
}
