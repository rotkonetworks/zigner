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

            // Use UR-encoded string for Zashi/Keystone QR compatibility
            // The ur_string is "ur:zcash-accounts/..." format
            val urBytes = export.urString.toByteArray(Charsets.UTF_8).map { it.toUByte() }
            val urQrPng = encodeToQr(urBytes, false)

            ZcashFvkExportResult(
                address = export.address,
                ufvk = export.ufvk,
                fvkHex = export.fvkHex,
                urString = export.urString,
                qrPng = urQrPng.toUByteArray().toList(),
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
    /** Unified Full Viewing Key (ZIP-316 format: "uview1..." or "uviewtest1...") */
    val ufvk: String,
    /** Raw FVK bytes as hex */
    val fvkHex: String,
    /** UR-encoded string for Zashi/Keystone QR compatibility ("ur:zcash-accounts/...") */
    val urString: String,
    /** QR code PNG of the UR string */
    val qrPng: List<UByte>,
    val label: String,
    val accountIndex: UInt,
    val mainnet: Boolean
)
