package net.rotko.zigner.screens.settings.networks.list

import androidx.lifecycle.ViewModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.backend.UniffiResult


internal class NetworkListViewModel : ViewModel() {
	private val uniffiInteractor = ServiceLocator.uniffiInteractor
	suspend fun getNetworkList(): UniffiResult<NetworksListModel> {
			return when (val result = uniffiInteractor.getAllNetworks()) {
				is UniffiResult.Error -> UniffiResult.Error(result.error)
				is UniffiResult.Success -> UniffiResult.Success(NetworksListModel(result.result))
			}
	}
}
