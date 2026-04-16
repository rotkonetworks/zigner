package net.rotko.zigner.screens.keysetdetails.export

import android.graphics.BitmapFactory
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Derives the ZID cross-site ed25519 public key from the master seed
 * and returns a "zid:<hex>" QR code as ImageBitmap.
 *
 * Zafu scans this QR on the identity page to associate a ZID
 * with a zigner (watch-only) wallet.
 */
class ZidExportService {

    suspend fun getZidQr(seedPhrase: String): ImageBitmap? =
        withContext(Dispatchers.IO) {
            try {
                val pngBytes = io.parity.signer.uniffi.deriveZidQr(seedPhrase)
                    .map { it.toByte() }
                    .toByteArray()
                BitmapFactory.decodeByteArray(pngBytes, 0, pngBytes.size)
                    ?.asImageBitmap()
            } catch (e: Exception) {
                null
            }
        }

    suspend fun getZidPubkey(seedPhrase: String): String? =
        withContext(Dispatchers.IO) {
            try {
                io.parity.signer.uniffi.deriveZid(seedPhrase)
            } catch (e: Exception) {
                null
            }
        }
}
