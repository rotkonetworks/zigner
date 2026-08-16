package net.rotko.zigner.screens.settings.frost

import io.parity.signer.uniffi.ageDeviceRecipient
import io.parity.signer.uniffi.frostExportAllBackupAge
import io.parity.signer.uniffi.frostExportAllBackupEnvelope
import io.parity.signer.uniffi.frostExportBackupEnvelope
import io.parity.signer.uniffi.frostImportAllBackupAge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.AuthResult
import net.rotko.zigner.domain.storage.mapError

/**
 * Single owner of the system-auth gate for FROST share export.
 *
 * A FROST backup envelope is encrypted with only a user-chosen passphrase, so
 * an unattended unlocked device would otherwise let anyone write a share to disk
 * and crack the passphrase offline. Every export path funnels through here so a
 * fresh biometric / device-credential check can't be bypassed by a future call
 * site — mirroring the auth gate already on online-mode toggle, seed export, and
 * device wipe. See rotkonetworks/zigner#14.
 *
 * Every helper returns null when authentication fails or is cancelled; callers
 * treat null as "aborted, do nothing" (the auth layer already surfaces its own
 * failure toast). A thrown exception still means a genuine export failure.
 *
 * The age helpers below gate on the seed read rather than on `authenticated()`.
 * That is not a weaker gate - reading a seed force-auths - but it is a
 * different one, and it must stay that way: doing both would prompt twice for
 * a single user action, and a second prompt is the kind of thing people learn
 * to dismiss without reading.
 */
object FrostExportUseCase {

	/** True only after a fresh, successful device authentication. */
	private suspend fun authenticated(): Boolean {
		val activity = ServiceLocator.activityScope?.activity ?: return false
		return ServiceLocator.authentication.authenticate(activity) == AuthResult.AuthSuccess
	}

	/** Export one wallet's encrypted backup envelope, gated on fresh auth. */
	suspend fun exportSingle(walletId: String, passphrase: String): String? {
		if (!authenticated()) return null
		return withContext(Dispatchers.Default) {
			frostExportBackupEnvelope(walletId, passphrase)
		}
	}

	/** Export every wallet into one encrypted envelope, gated on fresh auth. */
	suspend fun exportAll(passphrase: String): String? {
		if (!authenticated()) return null
		return withContext(Dispatchers.Default) {
			frostExportAllBackupEnvelope(passphrase)
		}
	}

	/**
	 * Export every wallet encrypted to public keys instead of a passphrase.
	 *
	 * The auth gate here is `getSeedPhraseForceAuth`, which is the same fresh
	 * device-credential check the two above make - reading the seed cannot
	 * happen without it. Calling `authenticated()` as well would only prompt
	 * the user twice for one action.
	 *
	 * `extraRecipients` are the co-signers. This device is always a recipient
	 * regardless, added in Rust so a UI mistake cannot produce a backup this
	 * device is unable to restore.
	 *
	 * Returns null if the seed read was cancelled or failed.
	 */
	suspend fun exportAllToRecipients(
		seedName: String,
		extraRecipients: List<String>,
	): String? {
		val repository = ServiceLocator.activityScope?.seedRepository ?: return null
		val phrase = repository.getSeedPhraseForceAuth(seedName).mapError() ?: return null
		return withContext(Dispatchers.Default) {
			frostExportAllBackupAge(phrase, extraRecipients)
		}
	}

	/** This device's recipient line, for showing and sharing. Force-auths. */
	suspend fun deviceRecipient(seedName: String): String? {
		val repository = ServiceLocator.activityScope?.seedRepository ?: return null
		val phrase = repository.getSeedPhraseForceAuth(seedName).mapError() ?: return null
		return withContext(Dispatchers.Default) { ageDeviceRecipient(phrase) }
	}

	/** Import an age-encrypted batch backup addressed to this device. */
	suspend fun importAllFromAge(seedName: String, armored: String): String? {
		val repository = ServiceLocator.activityScope?.seedRepository ?: return null
		val phrase = repository.getSeedPhraseForceAuth(seedName).mapError() ?: return null
		return withContext(Dispatchers.Default) {
			frostImportAllBackupAge(phrase, armored)
		}
	}
}
