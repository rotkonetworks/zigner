package net.rotko.zigner.domain.usecases

import net.rotko.zigner.domain.NetworkModel
import net.rotko.zigner.domain.backend.UniffiInteractor
import net.rotko.zigner.domain.backend.mapError
import net.rotko.zigner.domain.backend.mapErrorForce
import kotlinx.coroutines.runBlocking


class AllNetworksUseCase(val uniffiInteractor: UniffiInteractor) {

	fun getAllNetworks(): List<NetworkModel> = runBlocking { getNetworks() }

	// Zigner focuses on Zcash and Penumbra cold wallet signing
	private val preselectedkeys = listOf<String>("Zcash", "Penumbra")

	fun getDefaultPreselectedNetworks(): List<NetworkModel> = getAllNetworks()
		.filter { preselectedkeys.contains(it.title) }

	private suspend fun getNetworks(): List<NetworkModel> {
		return uniffiInteractor.getAllNetworks().mapErrorForce()
	}
}
