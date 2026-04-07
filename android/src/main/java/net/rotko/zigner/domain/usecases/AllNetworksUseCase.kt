package net.rotko.zigner.domain.usecases

import net.rotko.zigner.domain.NetworkModel
import net.rotko.zigner.domain.backend.UniffiInteractor
import net.rotko.zigner.domain.backend.mapError
import net.rotko.zigner.domain.backend.mapErrorForce
import kotlinx.coroutines.runBlocking


class AllNetworksUseCase(val uniffiInteractor: UniffiInteractor) {

	// Networks available in the UI. To re-enable cosmos/polkadot, add them here:
	// "Polkadot", "Kusama", "Osmosis", "Noble", "Celestia", etc.
	private val launchedNetworks = listOf("Zcash", "Penumbra")

	fun getAllNetworks(): List<NetworkModel> = runBlocking { getNetworks() }
		.filter { launchedNetworks.contains(it.title) }

	fun getDefaultPreselectedNetworks(): List<NetworkModel> = getAllNetworks()

	private suspend fun getNetworks(): List<NetworkModel> {
		return uniffiInteractor.getAllNetworks().mapErrorForce()
	}
}
