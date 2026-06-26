package net.rotko.zigner.screens.settings.frost

import io.parity.signer.uniffi.frostExportAllBackupEnvelope
import io.parity.signer.uniffi.frostExportBackupEnvelope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.AuthResult

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
 * Both helpers return null when authentication fails or is cancelled; callers
 * treat null as "aborted, do nothing" (the auth layer already surfaces its own
 * failure toast). A thrown exception still means a genuine export failure.
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
}
