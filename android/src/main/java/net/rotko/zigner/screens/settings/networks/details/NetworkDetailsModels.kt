package net.rotko.zigner.screens.settings.networks.details

import net.rotko.zigner.domain.encodeHex
import net.rotko.zigner.screens.scan.transaction.transactionElements.MetadataModel
import net.rotko.zigner.screens.scan.transaction.transactionElements.toMetadataModel
import net.rotko.zigner.ui.helpers.PreviewData
import io.parity.signer.uniffi.Identicon
import io.parity.signer.uniffi.MNetworkDetails
import io.parity.signer.uniffi.MVerifier


data class NetworkDetailsModel(
    val base58prefix: UShort,
//	val color: String,
    val decimals: UByte,
	val encryptionType: String,
    val genesisHash: String,
    val logo: String,
    val name: String,
//	val order: String,
//	val pathId: String,
//	val secondaryColor: String,
    val title: String,
    val unit: String,
    val currentVerifier: VerifierModel,
    val meta: List<MetadataModel>
) {
	companion object {
		fun createStub() = NetworkDetailsModel(
			base58prefix = 0u,
			decimals = 10.toUByte(),
			encryptionType = "sr25519",
			genesisHash = "5DCmwXp8XLzSMUyE4uhJMKV4vwvsWqqBYFKJq38CW53VHEVq",
			logo = "polkadot",
			name = "Polkadot",
			title = "Polkadot",
			unit = "DOT",
			currentVerifier = VerifierModel(
				"custom",
				"vwvsWqqBYFK",
				PreviewData.Identicon.dotIcon,
				"sr25519"
			),
			meta = listOf(MetadataModel.createStub(), MetadataModel.createStub())
		)
	}
}

fun MNetworkDetails.toNetworkDetailsModel() = NetworkDetailsModel(
	base58prefix = base58prefix,
	decimals = decimals,
	encryptionType = encryption.toString().lowercase(),
	genesisHash = genesisHash.toUByteArray().toByteArray().encodeHex(),
	logo = logo,
	name = name,
	title = title,
	unit = unit,
	currentVerifier = currentVerifier.toVerifierModel(),
	meta = meta.map { it.toMetadataModel() },
)

data class VerifierModel(
	val ttype: String,
	val publicKey: String,
	val identicon: Identicon,
	val encryption: String
)

fun MVerifier.toVerifierModel() = VerifierModel(
	ttype = ttype,
	publicKey = details.publicKey,
	identicon = details.identicon,
	encryption = details.encryption,
)
