package net.rotko.zigner.domain.security

import android.os.Build
import net.rotko.zigner.domain.FeatureFlags
import net.rotko.zigner.domain.FeatureOption
import timber.log.Timber
import java.io.File


/**
 * What the OS says about its own integrity, and what we can see on disk.
 *
 * Everything here is SELF-REPORTED. A compromised OS controls this process and
 * can return any value it likes, so a clean result is not evidence the device
 * is uncompromised. What a result CAN do is surface a state the owner may not
 * know about - an unlocked bootloader, a leftover su binary - and say what it
 * means. Verification that does not trust this phone needs hardware key
 * attestation checked from a second device (e.g. GrapheneOS Auditor).
 *
 * This replaces a root check that hard-blocked the app on finding `su` at a
 * few well-known paths. That check missed anything hiding itself (Magisk
 * does by default), so a pass meant nothing, while a hit only ever caught
 * people who rooted deliberately. Reporting and explaining is strictly more
 * honest than blocking on a heuristic.
 */
object DeviceIntegrity {

	/** `ro.boot.verifiedbootstate`, as defined by Android Verified Boot. */
	enum class BootState {
		/** Locked bootloader, OS signed by the OEM key. */
		GREEN,

		/**
		 * Locked bootloader, OS signed by a user-set key. This is the CORRECT
		 * state for GrapheneOS and other properly installed alternate OSes,
		 * not a warning: the OS is still verified, against a different key.
		 */
		YELLOW,

		/** Unlocked bootloader: the OS is not verified at boot at all. */
		ORANGE,

		/** Verification failed. Normally the device refuses to boot. */
		RED,

		/** Property unreadable or unrecognised. */
		UNKNOWN,
	}

	data class Report(
		val bootState: BootState,
		/** `ro.boot.vbmeta.device_state`: "locked" / "unlocked" / null if unreadable. */
		val deviceState: String?,
		/** Concrete things found, e.g. "/system/xbin/su". Empty means none found, not none present. */
		val rootEvidence: List<String>,
		/** The build is signed with AOSP test keys, which are public. */
		val testKeys: Boolean,
	) {
		val bootloaderUnlocked: Boolean
			get() = bootState == BootState.ORANGE || deviceState == "unlocked"

		/**
		 * Whether to stop at startup and explain. Unknown is not a reason:
		 * many OEM builds simply hide the property from apps, and a screen
		 * shown on every start for a non-finding teaches people to dismiss it.
		 */
		val needsAttention: Boolean
			get() = bootloaderUnlocked || bootState == BootState.RED ||
				rootEvidence.isNotEmpty() || testKeys
	}

	fun parseBootState(raw: String?): BootState = when (raw?.trim()?.lowercase()) {
		"green" -> BootState.GREEN
		"yellow" -> BootState.YELLOW
		"orange" -> BootState.ORANGE
		"red" -> BootState.RED
		else -> BootState.UNKNOWN
	}

	fun current(): Report {
		if (FeatureFlags.isEnabled(FeatureOption.SKIP_ROOTED_CHECK_EMULATOR)) {
			return Report(BootState.UNKNOWN, null, emptyList(), testKeys = false)
		}
		return Report(
			bootState = parseBootState(systemProperty("ro.boot.verifiedbootstate")),
			deviceState = systemProperty("ro.boot.vbmeta.device_state")
				?.trim()?.lowercase()?.takeIf { it.isNotEmpty() },
			rootEvidence = SU_PATHS.filter { File(it).exists() },
			testKeys = Build.TAGS?.contains("test-keys") == true,
		).also { Timber.d("device integrity: $it") }
	}

	/**
	 * Reads a system property through the hidden SystemProperties API.
	 * Returns null rather than guessing when it is unavailable - the hidden
	 * API can be blocked and SELinux can deny the read, and either must show
	 * as UNKNOWN, never as a pass.
	 */
	private fun systemProperty(name: String): String? = try {
		val cls = Class.forName("android.os.SystemProperties")
		val get = cls.getMethod("get", String::class.java)
		(get.invoke(null, name) as? String)?.takeIf { it.isNotEmpty() }
	} catch (t: Throwable) {
		Timber.d("cannot read $name: $t")
		null
	}

	private val SU_PATHS = listOf(
		"/system/app/Superuser.apk",
		"/sbin/su",
		"/system/bin/su",
		"/system/xbin/su",
		"/data/local/xbin/su",
		"/data/local/bin/su",
		"/system/sd/xbin/su",
		"/system/bin/failsafe/su",
		"/data/local/su",
		"/su/bin/su",
	)
}
