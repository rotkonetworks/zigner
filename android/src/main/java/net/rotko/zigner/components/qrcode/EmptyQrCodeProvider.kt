package net.rotko.zigner.components.qrcode

import net.rotko.zigner.domain.backend.UniffiInteractor
import net.rotko.zigner.domain.backend.mapError
import net.rotko.zigner.dependencygraph.ServiceLocator


/**
 * Get ready key into into qr image
 */
class EmptyQrCodeProvider : AnimatedQrKeysProvider<List<List<UByte>>> {
	private val uniffiInteractor: UniffiInteractor =
		ServiceLocator.uniffiInteractor

	override suspend fun getQrCodesList(input: List<List<UByte>>): AnimatedQrImages? {
		return uniffiInteractor.encodeToQrImages(input).mapError()
			?.let { AnimatedQrImages(it) }
	}
}
