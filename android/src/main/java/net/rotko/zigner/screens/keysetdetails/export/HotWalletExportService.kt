package net.rotko.zigner.screens.keysetdetails.export

import android.graphics.BitmapFactory
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.rotko.zigner.dependencygraph.ServiceLocator

/**
 * Derives the hot wallet mnemonic from the master seed and returns
 * a static QR code (ur:zafu-hot-wallet) as ImageBitmap.
 *
 * The hot wallet is a deterministic 12-word BIP39 mnemonic derived
 * from the cold wallet seed via HMAC-SHA512("hot-wallet-v1").
 * Zafu scans this QR to create a hot wallet for ZID, pro subscription,
 * and daily spending.
 */
class HotWalletExportService {

    suspend fun getHotWalletQr(seedPhrase: String): ImageBitmap? =
        withContext(Dispatchers.IO) {
            try {
                val pngBytes = io.parity.signer.uniffi.deriveHotWalletQr(seedPhrase)
                    .map { it.toByte() }
                    .toByteArray()
                BitmapFactory.decodeByteArray(pngBytes, 0, pngBytes.size)
                    ?.asImageBitmap()
            } catch (e: Exception) {
                null
            }
        }
}
