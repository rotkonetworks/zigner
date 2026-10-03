package net.rotko.zigner.domain.security

import android.os.Build
import java.util.Calendar


/**
 * Android security patch level, and how far behind it is.
 *
 * The patch level is the single most informative number about the OS this
 * signer runs on: it says which published vulnerabilities are fixed. It is
 * also self-reported by the OS, and "how far behind" is computed against the
 * device clock - which on an air-gapped phone with no network time can be
 * wrong. Both caveats belong next to the number wherever it is shown.
 */
object SecurityPatch {

	/**
	 * Months behind at which we warn. Pixels and GrapheneOS ship monthly;
	 * three months lets a release slip without crying wolf, and is still
	 * short enough that a remotely exploitable bug fixed in a bulletin is
	 * not sitting open on a device that holds keys.
	 */
	const val STALE_AFTER_MONTHS = 3

	data class PatchMonth(val year: Int, val month: Int) {
		/** Months since year 0, for subtraction. [month] is 1-based. */
		val index: Int get() = year * 12 + (month - 1)

		override fun toString(): String = "%04d-%02d".format(year, month)
	}

	/**
	 * Parses `Build.VERSION.SECURITY_PATCH` ("2026-09-05"). Only year and
	 * month are meaningful: the day is 01 or 05, which selects between the
	 * two halves of a monthly bulletin, not a calendar day.
	 *
	 * Returns null for anything else rather than throwing - this is OS input,
	 * and a custom ROM with an unexpected format must not break startup.
	 */
	fun parse(raw: String?): PatchMonth? {
		val match = raw?.trim()?.let { PATTERN.matchEntire(it) } ?: return null
		val year = match.groupValues[1].toInt()
		val month = match.groupValues[2].toInt()
		if (month !in 1..12) return null
		return PatchMonth(year, month)
	}

	/** Whole months from [patch] to [now]; negative if the clock is behind the patch. */
	fun monthsBehind(patch: PatchMonth, now: PatchMonth): Int = now.index - patch.index

	sealed interface Status {
		val raw: String?

		/** Patch is recent relative to the device clock. */
		data class Current(override val raw: String, val patch: PatchMonth, val monthsBehind: Int) : Status

		/** Patch is [monthsBehind] months old relative to the device clock. */
		data class Stale(override val raw: String, val patch: PatchMonth, val monthsBehind: Int) : Status

		/**
		 * The device clock is earlier than the patch month, so the clock is
		 * wrong and no age can be computed. Not a reason to trust the patch
		 * more - only a reason not to print a number we cannot stand behind.
		 */
		data class ClockBehind(override val raw: String, val patch: PatchMonth) : Status

		/** The OS reported nothing parseable. */
		data class Unknown(override val raw: String?) : Status
	}

	fun evaluate(raw: String?, now: PatchMonth): Status {
		val patch = parse(raw) ?: return Status.Unknown(raw)
		val behind = monthsBehind(patch, now)
		return when {
			behind < 0 -> Status.ClockBehind(raw!!, patch)
			behind >= STALE_AFTER_MONTHS -> Status.Stale(raw!!, patch, behind)
			else -> Status.Current(raw!!, patch, behind)
		}
	}

	fun current(): Status {
		val cal = Calendar.getInstance()
		val now = PatchMonth(cal.get(Calendar.YEAR), cal.get(Calendar.MONTH) + 1)
		return evaluate(Build.VERSION.SECURITY_PATCH, now)
	}

	private val PATTERN = Regex("""(\d{4})-(\d{2})-(\d{2})""")
}
