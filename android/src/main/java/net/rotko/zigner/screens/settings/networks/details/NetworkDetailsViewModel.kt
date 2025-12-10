package net.rotko.zigner.screens.settings.networks.details

import androidx.lifecycle.ViewModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.backend.UniffiResult


class NetworkDetailsViewModel : ViewModel() {

	private val uniffiInteractor = ServiceLocator.uniffiInteractor
	suspend fun getNetworkDetails(networkKey: String): UniffiResult<NetworkDetailsModel> {
		return uniffiInteractor.getManagedNetworkDetails(networkKey)
	}

	suspend fun removeNetwork(networkKey: String): UniffiResult<Unit> {
		return uniffiInteractor.removeManagedNetwork(networkKey)
	}

	suspend fun removeNetworkMetadata(
		networkKey: String,
		metadataSpecsVersion: String
	): UniffiResult<Unit> {
		return uniffiInteractor.removeMetadataManagedNetwork(
			networkKey,
			metadataSpecsVersion
		)
	}
}
