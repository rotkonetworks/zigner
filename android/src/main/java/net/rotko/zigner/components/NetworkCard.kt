package net.rotko.zigner.components

import io.parity.signer.uniffi.MscNetworkInfo

/**
 * The NetworkCard composable (network chip UI) was deleted along with the
 * substrate network-management screens it was drawn for. This model and its
 * extension stay: PrivateKeyExportBottomSheet.kt still builds one from
 * MscNetworkInfo to label an exported key's network.
 */
class NetworkCardModel(
	val networkTitle: String,
	val networkLogo: String,
)

fun MscNetworkInfo.toNetworkCardModel(): NetworkCardModel =
	NetworkCardModel(
		networkTitle = networkTitle.replaceFirstChar {
			if (it.isLowerCase()) it.titlecase() else it.toString()
		},
		networkLogo = networkLogo,
	)
