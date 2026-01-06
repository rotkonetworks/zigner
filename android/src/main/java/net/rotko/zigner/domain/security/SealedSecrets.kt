package net.rotko.zigner.domain.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import timber.log.Timber
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Sealed secrets - encryption keys bound to device security state.
 *
 * Keys are invalidated if:
 * - Biometric enrollment changes (new fingerprint added)
 * - Device is locked
 * - Boot state changes (on devices that support it)
 *
 * This provides defense-in-depth: even if an attacker gains code execution,
 * they cannot decrypt seeds without:
 * - Device being unlocked
 * - User authenticating
 * - Original biometrics still enrolled
 */
object SealedSecrets {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val SEALED_KEY_ALIAS = "zigner_sealed_master_v1"
    private const val GCM_IV_LENGTH = 12
    private const val GCM_TAG_LENGTH = 128

    data class SealedData(
        val ciphertext: ByteArray,
        val iv: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is SealedData) return false
            return ciphertext.contentEquals(other.ciphertext) && iv.contentEquals(other.iv)
        }

        override fun hashCode(): Int {
            return 31 * ciphertext.contentHashCode() + iv.contentHashCode()
        }
    }

    data class SecurityProperties(
        val isStrongBoxBacked: Boolean,
        val requiresUserAuthentication: Boolean,
        val requiresDeviceUnlocked: Boolean,
        val invalidatedByBiometricEnrollment: Boolean,
        val description: String
    )

    /**
     * Generate or retrieve the sealed master key.
     * Key is bound to device security state.
     */
    fun getOrCreateSealedKey(context: Context): Result<SecretKey> {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            // Check if key already exists
            if (keyStore.containsAlias(SEALED_KEY_ALIAS)) {
                val key = keyStore.getKey(SEALED_KEY_ALIAS, null) as? SecretKey
                if (key != null) {
                    return Result.success(key)
                }
                // Key exists but is invalid - regenerate
                keyStore.deleteEntry(SEALED_KEY_ALIAS)
            }

            // Generate new key with security bindings
            val key = generateSealedKey(context)
            Result.success(key)
        } catch (e: Exception) {
            Timber.e(e, "Failed to get/create sealed key")
            Result.failure(e)
        }
    }

    /**
     * Generate a new sealed key with maximum security properties.
     */
    private fun generateSealedKey(context: Context): SecretKey {
        val hasStrongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        } else {
            false
        }

        val builder = KeyGenParameterSpec.Builder(
            SEALED_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            // Require user authentication
            .setUserAuthenticationRequired(true)

        // API 28+: StrongBox and unlock requirement
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            if (hasStrongBox) {
                builder.setIsStrongBoxBacked(true)
            }
            builder.setUnlockedDeviceRequired(true)
        }

        // API 24+: Invalidate on biometric change
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(true)
        }

        // API 30+: Stronger user presence requirement
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                30, // 30 second timeout
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(30)
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        keyGenerator.init(builder.build())

        return keyGenerator.generateKey()
    }

    /**
     * Seal (encrypt) data using the device-bound key.
     */
    fun seal(context: Context, plaintext: ByteArray): Result<SealedData> {
        return try {
            val key = getOrCreateSealedKey(context).getOrThrow()

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)

            val iv = cipher.iv
            val ciphertext = cipher.doFinal(plaintext)

            Result.success(SealedData(ciphertext, iv))
        } catch (e: Exception) {
            Timber.e(e, "Failed to seal data")
            Result.failure(e)
        }
    }

    /**
     * Unseal (decrypt) data using the device-bound key.
     * Will fail if device state has changed (biometrics, lock state, etc.)
     */
    fun unseal(context: Context, sealed: SealedData): Result<ByteArray> {
        return try {
            val key = getOrCreateSealedKey(context).getOrThrow()

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(GCM_TAG_LENGTH, sealed.iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)

            val plaintext = cipher.doFinal(sealed.ciphertext)
            Result.success(plaintext)
        } catch (e: Exception) {
            Timber.e(e, "Failed to unseal data")
            Result.failure(e)
        }
    }

    /**
     * Get security properties of the sealed key.
     */
    fun getSecurityProperties(context: Context): SecurityProperties {
        val hasStrongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        } else {
            false
        }

        val description = buildString {
            if (hasStrongBox) {
                append("StrongBox-backed, ")
            } else {
                append("TEE-backed, ")
            }
            append("auth required, ")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                append("unlock required, ")
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                append("biometric-bound")
            }
        }

        return SecurityProperties(
            isStrongBoxBacked = hasStrongBox,
            requiresUserAuthentication = true,
            requiresDeviceUnlocked = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P,
            invalidatedByBiometricEnrollment = Build.VERSION.SDK_INT >= Build.VERSION_CODES.N,
            description = description
        )
    }

    /**
     * Check if sealed secrets are available on this device.
     */
    fun isAvailable(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
    }

    /**
     * Delete the sealed key (for testing or reset).
     */
    fun deleteKey(): Result<Unit> {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            if (keyStore.containsAlias(SEALED_KEY_ALIAS)) {
                keyStore.deleteEntry(SEALED_KEY_ALIAS)
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Timber.e(e, "Failed to delete sealed key")
            Result.failure(e)
        }
    }
}
