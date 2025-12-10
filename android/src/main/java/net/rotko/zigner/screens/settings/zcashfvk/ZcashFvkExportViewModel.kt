package net.rotko.zigner.screens.settings.zcashfvk

import androidx.lifecycle.ViewModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.storage.mapError
import io.parity.signer.uniffi.encodeToQr
import io.parity.signer.uniffi.exportZcashFvk

internal class ZcashFvkExportViewModel : ViewModel() {

    private val seedStorage = ServiceLocator.seedStorage
    private val seedRepository = ServiceLocator.activityScope!!.seedRepository

    fun getSeeds(): List<String> {
        return seedStorage.getSeedNames().toList()
    }

    suspend fun exportFvk(
        seedName: String,
        accountIndex: UInt = 0u,
        label: String = "",
        mainnet: Boolean = true
    ): ZcashFvkExportResult? {
        // Get the seed phrase with biometric auth
        val seedPhrase = seedRepository.getSeedPhraseForceAuth(seedName).mapError()
            ?: return null

        return try {
            val export = exportZcashFvk(seedPhrase, accountIndex, label, mainnet)

            // Encode QR data as PNG
            val qrPng = encodeToQr(export.qrData, false)

            ZcashFvkExportResult(
                address = export.address,
                fvkHex = export.fvkHex,
                qrPng = qrPng.toUByteArray().toList(),
                label = export.label,
                accountIndex = export.accountIndex,
                mainnet = export.mainnet
            )
        } catch (e: Exception) {
            null
        }
    }
}

data class ZcashFvkExportResult(
    val address: String,
    val fvkHex: String,
    val qrPng: List<UByte>,
    val label: String,
    val accountIndex: UInt,
    val mainnet: Boolean
)
