package net.rotko.zigner.domain.security

import net.rotko.zigner.domain.security.SecurityPatch.PatchMonth
import net.rotko.zigner.domain.security.SecurityPatch.Status
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityPatchTest {

	// Regression: the previous parser used SimpleDateFormat("yyyy-MM-DD"),
	// where DD is day-of-YEAR and overrides the month - "2024-11-05" parsed
	// as January 5th. Its only test used a January date, which hid it.
	@Test
	fun parseKeepsMonthForNonJanuaryPatch() {
		assertEquals(PatchMonth(2024, 11), SecurityPatch.parse("2024-11-05"))
		assertEquals(PatchMonth(2026, 9), SecurityPatch.parse("2026-09-01"))
	}

	@Test
	fun parseRejectsMalformedWithoutThrowing() {
		assertNull(SecurityPatch.parse(null))
		assertNull(SecurityPatch.parse(""))
		assertNull(SecurityPatch.parse("2024/11/05"))
		assertNull(SecurityPatch.parse("2024-13-05"))
		assertNull(SecurityPatch.parse("2024-00-05"))
		assertNull(SecurityPatch.parse("Nov 2024"))
	}

	@Test
	fun monthsBehindCrossesYearBoundary() {
		assertEquals(2, SecurityPatch.monthsBehind(PatchMonth(2025, 11), PatchMonth(2026, 1)))
		assertEquals(0, SecurityPatch.monthsBehind(PatchMonth(2026, 1), PatchMonth(2026, 1)))
	}

	@Test
	fun thresholdIsInclusive() {
		val now = PatchMonth(2026, 10)
		val justUnder = SecurityPatch.evaluate("2026-08-05", now)
		val atThreshold = SecurityPatch.evaluate("2026-07-01", now)
		assertTrue(justUnder is Status.Current)
		assertTrue(atThreshold is Status.Stale)
		assertEquals(SecurityPatch.STALE_AFTER_MONTHS, (atThreshold as Status.Stale).monthsBehind)
	}

	// An offline phone's clock can be anywhere. A patch "from the future"
	// means the clock is wrong; we must not print an age, and must not call
	// it current either.
	@Test
	fun clockEarlierThanPatchIsNotAnAge() {
		val status = SecurityPatch.evaluate("2026-09-05", PatchMonth(2020, 1))
		assertTrue(status is Status.ClockBehind)
	}

	@Test
	fun unparseableIsUnknownNotCurrent() {
		assertTrue(SecurityPatch.evaluate("garbage", PatchMonth(2026, 10)) is Status.Unknown)
	}
}
