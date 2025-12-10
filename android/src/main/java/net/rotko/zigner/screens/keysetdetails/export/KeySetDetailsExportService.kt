package net.rotko.zigner.screens.keysetdetails.export

import net.rotko.zigner.domain.backend.UniffiInteractor
import net.rotko.zigner.domain.backend.mapError
import net.rotko.zigner.components.qrcode.AnimatedQrImages
import net.rotko.zigner.components.qrcode.AnimatedQrKeysProvider
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.KeyModel
import net.rotko.zigner.domain.getData


class KeySetDetailsExportService :
	AnimatedQrKeysProvider<KeySetDetailsExportService.GetQrCodesListRequest> {
	private val uniffiInteractor: UniffiInteractor =
		ServiceLocator.uniffiInteractor

	override suspend fun getQrCodesList(input: GetQrCodesListRequest): AnimatedQrImages? {
		return uniffiInteractor.exportSeedWithKeys(
			seed = input.seedName,
			derivedKeyAddr = input.keys.map { key -> key.addressKey })
			.mapError()
			?.let { keyInfo -> uniffiInteractor.encodeToQrImages(keyInfo.frames.map { it.getData() }) }
			?.mapError()
			?.let { AnimatedQrImages(it) }
	}

	data class GetQrCodesListRequest(
		val seedName: String,
		val keys: List<KeyModel>,
	)
}
