package net.rotko.zigner.screens.settings.penumbrafvk

import androidx.lifecycle.ViewModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.storage.mapError
import io.parity.signer.uniffi.PenumbraFvkExport
import io.parity.signer.uniffi.encodeToQr
import io.parity.signer.uniffi.exportPenumbraFvk

internal class PenumbraFvkExportViewModel : ViewModel() {

    private val seedStorage = ServiceLocator.seedStorage
    private val seedRepository = ServiceLocator.activityScope!!.seedRepository

    fun getSeeds(): List<String> {
        return seedStorage.getSeedNames().toList()
    }

    suspend fun exportFvk(
        seedName: String,
        accountIndex: UInt = 0u,
        label: String = ""
    ): PenumbraFvkExportResult? {
        // Get the seed phrase with biometric auth
        val seedPhrase = seedRepository.getSeedPhraseForceAuth(seedName).mapError()
            ?: return null

        return try {
            val export = exportPenumbraFvk(seedPhrase, accountIndex, label)

            // Encode QR data as PNG
            val qrPng = encodeToQr(export.qrData, false)

            PenumbraFvkExportResult(
                fvkBech32m = export.fvkBech32m,
                walletIdBech32m = export.walletIdBech32m,
                qrPng = qrPng.toUByteArray().toList(),
                label = export.label,
                accountIndex = export.accountIndex
            )
        } catch (e: Exception) {
            null
        }
    }
}

data class PenumbraFvkExportResult(
    val fvkBech32m: String,
    val walletIdBech32m: String,
    val qrPng: List<UByte>,
    val label: String,
    val accountIndex: UInt
)
