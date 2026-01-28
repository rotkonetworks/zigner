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
    val decimals: UByte,
    val encryption: String,
    val genesisHash: String,
    val logo: String,
    val name: String,
    val title: String,
    val unit: String,
    val currentVerifier: VerifierModel,
    val meta: List<MetadataModel>
) {
	/** Substrate networks use verifier certificates for metadata updates */
	val isSubstrate: Boolean
		get() = encryption in listOf("sr25519", "ed25519", "ecdsa")

	companion object {
		fun createStub() = NetworkDetailsModel(
			base58prefix = 0u,
			decimals = 10.toUByte(),
			encryption = "sr25519",
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
	encryption = encryption.toDisplayName(),
	genesisHash = genesisHash.toUByteArray().toByteArray().encodeHex(),
	logo = logo,
	name = name,
	title = title,
	unit = unit,
	currentVerifier = currentVerifier.toVerifierModel(),
	meta = meta.map { it.toMetadataModel() },
)

fun io.parity.signer.uniffi.Encryption.toDisplayName(): String = when (this) {
	io.parity.signer.uniffi.Encryption.ED25519 -> "ed25519"
	io.parity.signer.uniffi.Encryption.SR25519 -> "sr25519"
	io.parity.signer.uniffi.Encryption.ECDSA -> "ecdsa"
	io.parity.signer.uniffi.Encryption.ETHEREUM -> "secp256k1"
	io.parity.signer.uniffi.Encryption.PENUMBRA -> "decaf377"
	io.parity.signer.uniffi.Encryption.ZCASH -> "ed25519-zebra"
	io.parity.signer.uniffi.Encryption.LEDGER_ED25519 -> "ed25519-bip32"
	io.parity.signer.uniffi.Encryption.COSMOS -> "secp256k1"
	io.parity.signer.uniffi.Encryption.BITCOIN -> "secp256k1-schnorr"
	io.parity.signer.uniffi.Encryption.NOSTR -> "secp256k1-schnorr"
	io.parity.signer.uniffi.Encryption.AT_PROTOCOL -> "secp256k1"
}

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
