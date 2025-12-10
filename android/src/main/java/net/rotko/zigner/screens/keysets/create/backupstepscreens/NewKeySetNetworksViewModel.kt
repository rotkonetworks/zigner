package net.rotko.zigner.screens.keysets.create.backupstepscreens

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.NetworkModel
import net.rotko.zigner.domain.backend.AuthOperationResult
import net.rotko.zigner.domain.usecases.AllNetworksUseCase
import net.rotko.zigner.domain.usecases.CreateKeySetUseCase
import kotlinx.coroutines.launch


class NewKeySetNetworksViewModel : ViewModel() {
	private val uniffiInteractor = ServiceLocator.uniffiInteractor
	private val allNetworksUseCase = AllNetworksUseCase(uniffiInteractor)
	private val createKeySetUseCase = CreateKeySetUseCase()

	fun getAllNetworks(): List<NetworkModel> = allNetworksUseCase.getAllNetworks()

	fun getDefaultPreselectedNetworks(): List<NetworkModel> =
		allNetworksUseCase.getDefaultPreselectedNetworks()

	fun createKeySetWithNetworks(
		seedName: String, seedPhrase: String,
		networkForKeys: Set<NetworkModel>,
		onAfterCreate: (AuthOperationResult) -> Unit = {},
	): Unit {
		viewModelScope.launch {
			val success = createKeySetUseCase.createKeySetWithNetworks(
				seedName, seedPhrase,
				networkForKeys.map { it.key },
			)
			onAfterCreate(success)
		}
	}
}
