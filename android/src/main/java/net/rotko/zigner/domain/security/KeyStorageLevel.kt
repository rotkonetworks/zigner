package net.rotko.zigner.domain.security

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.security.crypto.MasterKey
import timber.log.Timber
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory


/**
 * Where the key that encrypts seeds at rest ACTUALLY lives, read back from
 * the keystore.
 *
 * `MasterKey.isStrongBoxBacked` cannot answer this: in security-crypto
 * 1.1.0-alpha06 it returns whether the KeyGenParameterSpec *requested*
 * StrongBox, not where the key ended up. It also describes the spec of the
 * caller, while `MasterKeys.getOrCreate` silently reuses an existing key
 * under the same alias - so for a key created earlier it describes nothing.
 *
 * What this key protects, stated precisely: it wraps the Tink keyset that
 * EncryptedSharedPreferences uses for the seed file. The keystore is used
 * ONCE, when SeedStorage.init unwraps that keyset (behind the screen-lock
 * prompt); after that, seeds are decrypted in software inside this process
 * with no further keystore involvement, so later reads are NOT gated by
 * the screen lock unless the caller prompts itself (getSeedPhraseForceAuth).
 * Neither StrongBox nor the TEE ever holds or uses the seed itself.
 */
object KeyStorageLevel {

	enum class Level {
		/** Dedicated secure element (e.g. Titan M2). */
		STRONGBOX,

		/** TrustZone / trusted execution environment. */
		TEE,

		/** Hardware-backed, but the OS does not say which kind (API < 31). */
		SECURE_HARDWARE,

		/** Software keystore: the key is only as safe as the OS. */
		SOFTWARE,

		/** Key absent or unreadable. */
		UNKNOWN,
	}

	fun of(alias: String = MasterKey.DEFAULT_MASTER_KEY_ALIAS): Level = try {
		read(alias)
	} catch (t: Throwable) {
		Timber.d("cannot read key info: $t")
		Level.UNKNOWN
	}

	private fun read(alias: String): Level {
		val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
		val key = ks.getKey(alias, null) as? SecretKey ?: return Level.UNKNOWN
		val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
			.getKeySpec(key, KeyInfo::class.java) as KeyInfo
		return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
			when (info.securityLevel) {
				KeyProperties.SECURITY_LEVEL_STRONGBOX -> Level.STRONGBOX
				KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> Level.TEE
				KeyProperties.SECURITY_LEVEL_SOFTWARE -> Level.SOFTWARE
				else -> Level.UNKNOWN
			}
		} else {
			@Suppress("DEPRECATION")
			if (info.isInsideSecureHardware) Level.SECURE_HARDWARE else Level.SOFTWARE
		}
	}

	fun describe(level: Level): String = when (level) {
		Level.STRONGBOX -> "StrongBox"
		Level.TEE -> "TEE"
		Level.SECURE_HARDWARE -> "Hardware keystore"
		Level.SOFTWARE -> "Software keystore"
		Level.UNKNOWN -> "Keystore unknown"
	}
}
