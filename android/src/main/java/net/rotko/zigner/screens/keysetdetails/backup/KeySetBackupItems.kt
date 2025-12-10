package net.rotko.zigner.screens.keysetdetails.backup

import net.rotko.zigner.domain.KeyAndNetworkModel
import net.rotko.zigner.domain.KeySetDetailsModel

data class SeedBackupModel(
	val seedName: String,
	val seedBase58: String,
	val derivations: List<KeyAndNetworkModel>
)
fun KeySetDetailsModel.toSeedBackupModel(): SeedBackupModel? {
	val root = root ?: return null
	return SeedBackupModel(root.seedName, root.base58, keysAndNetwork)
}
