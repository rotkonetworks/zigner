package net.rotko.zigner.screens.settings.networks.signspecs.view

import net.rotko.zigner.domain.backend.mapError
import net.rotko.zigner.dependencygraph.ServiceLocator
import kotlinx.coroutines.runBlocking


object SufficientCryptoReadyViewModel {
	fun getQrCodeBitmapFromQrCodeData(data: List<UByte>): List<UByte>? {
		val interactor = ServiceLocator.uniffiInteractor
		return runBlocking {
			interactor.encodeToQrImages(listOf(data))
				.mapError()
				?.firstOrNull()
		}
	}
}
