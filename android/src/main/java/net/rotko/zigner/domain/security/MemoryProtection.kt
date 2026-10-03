package net.rotko.zigner.domain.security

import android.os.Build
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.NativeLong
import timber.log.Timber

/**
 * Memory Tagging Extension (MTE) status of THIS process, as the kernel sees it.
 *
 * Two separate facts, both read from the kernel rather than inferred:
 *
 *  - hardware: `getauxval(AT_HWCAP2) & HWCAP2_MTE`. The kernel only sets this
 *    when the CPU has MTE AND it is enabled for userspace - on a stock Pixel 8
 *    that is off unless turned on in developer options, so a Tensor G3 does not
 *    by itself mean MTE is available.
 *  - this process: `prctl(PR_GET_TAGGED_ADDR_CTRL)`, whose tag-check-fault
 *    bits say whether tag mismatches actually fault.
 *
 * The previous implementation read a `MemTag:` line from /proc/self/status
 * (there is no such field), and on any read error assumed MTE was enabled;
 * hardware support fell back to matching model names. It could report "MTE"
 * for a process that had none.
 *
 * Note: Android enables PR_TAGGED_ADDR_ENABLE on all arm64 devices for heap
 * pointer tagging (Top Byte Ignore), with or without MTE. That bit alone
 * means nothing here - only the TCF bits do.
 */
object MemoryProtection {

	enum class MteMode {
		/** Tag mismatch faults immediately, at the faulting instruction. */
		SYNC,

		/** Tag mismatch is detected asynchronously, at the next kernel entry. */
		ASYNC,

		/** Kernel picks sync or async per CPU (both TCF bits set). */
		SYNC_OR_ASYNC,

		/** Tag checks do not fault in this process. */
		OFF,

		/** Could not ask the kernel. Must be shown as unknown, never as on. */
		UNKNOWN,
	}

	data class MteStatus(
		/** null = could not determine. */
		val hardwareAvailable: Boolean?,
		val mode: MteMode,
	) {
		val active: Boolean
			get() = mode == MteMode.SYNC || mode == MteMode.ASYNC || mode == MteMode.SYNC_OR_ASYNC
	}

	// linux/prctl.h
	private const val PR_GET_TAGGED_ADDR_CTRL = 56
	private const val PR_MTE_TCF_SYNC = 1 shl 1
	private const val PR_MTE_TCF_ASYNC = 1 shl 2

	// linux/auxvec.h, arch/arm64 uapi hwcap.h
	private const val AT_HWCAP2 = 26L
	private const val HWCAP2_MTE = 1L shl 18

	/** Decodes the `prctl(PR_GET_TAGGED_ADDR_CTRL)` result. Negative = call failed. */
	fun decodeTaggedAddrCtrl(ctrl: Int): MteMode {
		if (ctrl < 0) return MteMode.UNKNOWN
		val sync = ctrl and PR_MTE_TCF_SYNC != 0
		val async = ctrl and PR_MTE_TCF_ASYNC != 0
		return when {
			sync && async -> MteMode.SYNC_OR_ASYNC
			sync -> MteMode.SYNC
			async -> MteMode.ASYNC
			else -> MteMode.OFF
		}
	}

	fun decodeHwcap2(hwcap2: Long): Boolean = hwcap2 and HWCAP2_MTE != 0L

	@Suppress("FunctionName")
	private interface LibC : Library {
		fun prctl(option: Int, arg2: NativeLong, arg3: NativeLong, arg4: NativeLong, arg5: NativeLong): Int
		fun getauxval(type: NativeLong): NativeLong
	}

	private val libc: LibC? by lazy {
		try {
			Native.load("c", LibC::class.java)
		} catch (t: Throwable) {
			Timber.d("libc unavailable via JNA: $t")
			null
		}
	}

	fun getMteStatus(): MteStatus {
		// MTE is arm64-only and userspace support arrived in Android 12.
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S ||
			Build.SUPPORTED_ABIS.none { it == "arm64-v8a" }
		) {
			return MteStatus(hardwareAvailable = false, mode = MteMode.OFF)
		}
		val c = libc ?: return MteStatus(hardwareAvailable = null, mode = MteMode.UNKNOWN)

		val hardware = try {
			decodeHwcap2(c.getauxval(NativeLong(AT_HWCAP2)).toLong())
		} catch (t: Throwable) {
			Timber.d("getauxval failed: $t")
			null
		}
		val mode = try {
			val zero = NativeLong(0)
			decodeTaggedAddrCtrl(c.prctl(PR_GET_TAGGED_ADDR_CTRL, zero, zero, zero, zero))
		} catch (t: Throwable) {
			Timber.d("prctl failed: $t")
			MteMode.UNKNOWN
		}
		return MteStatus(hardwareAvailable = hardware, mode = mode)
	}

	fun describe(status: MteStatus): String = when {
		status.mode == MteMode.SYNC -> "MTE on (synchronous)"
		status.mode == MteMode.ASYNC -> "MTE on (asynchronous)"
		status.mode == MteMode.SYNC_OR_ASYNC -> "MTE on (sync/async per CPU)"
		status.mode == MteMode.UNKNOWN -> "MTE status unknown"
		status.hardwareAvailable == true -> "MTE available, not enabled for Zigner"
		status.hardwareAvailable == false -> "MTE not available on this device"
		else -> "MTE off"
	}
}
