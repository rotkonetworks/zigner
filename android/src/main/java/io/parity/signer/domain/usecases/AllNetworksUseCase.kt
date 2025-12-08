package io.parity.signer.domain.usecases

import io.parity.signer.domain.NetworkModel
import io.parity.signer.domain.backend.UniffiInteractor
import io.parity.signer.domain.backend.mapError
import io.parity.signer.domain.backend.mapErrorForce
import kotlinx.coroutines.runBlocking


class AllNetworksUseCase(val uniffiInteractor: UniffiInteractor) {

	fun getAllNetworks(): List<NetworkModel> = runBlocking { getNetworks() }

	// Zigner focuses on Penumbra cold wallet signing
	private val preselectedkeys = listOf<String>("Penumbra")

	fun getDefaultPreselectedNetworks(): List<NetworkModel> = getAllNetworks()
		.filter { preselectedkeys.contains(it.title) }

	private suspend fun getNetworks(): List<NetworkModel> {
		return uniffiInteractor.getAllNetworks().mapErrorForce()
	}
}
