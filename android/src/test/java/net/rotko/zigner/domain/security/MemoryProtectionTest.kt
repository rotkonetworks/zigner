package net.rotko.zigner.domain.security

import net.rotko.zigner.domain.security.MemoryProtection.MteMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MemoryProtectionTest {

	// PR_TAGGED_ADDR_ENABLE (bit 0) is set on every arm64 Android process for
	// heap pointer tagging via TBI, MTE or not. It must not read as "MTE on".
	@Test
	fun taggedAddrEnableAloneIsOff() {
		assertEquals(MteMode.OFF, MemoryProtection.decodeTaggedAddrCtrl(0x1))
		assertEquals(MteMode.OFF, MemoryProtection.decodeTaggedAddrCtrl(0x0))
	}

	@Test
	fun decodesTagCheckFaultModes() {
		// PR_MTE_TCF_SYNC = 1<<1, PR_MTE_TCF_ASYNC = 1<<2; tag include mask in bits 3..18
		assertEquals(MteMode.SYNC, MemoryProtection.decodeTaggedAddrCtrl(0x1 or 0x2 or (0xfffe shl 3)))
		assertEquals(MteMode.ASYNC, MemoryProtection.decodeTaggedAddrCtrl(0x1 or 0x4))
		assertEquals(MteMode.SYNC_OR_ASYNC, MemoryProtection.decodeTaggedAddrCtrl(0x1 or 0x2 or 0x4))
	}

	@Test
	fun failedCallIsUnknownNotOn() {
		val mode = MemoryProtection.decodeTaggedAddrCtrl(-1)
		assertEquals(MteMode.UNKNOWN, mode)
		assertFalse(MemoryProtection.MteStatus(null, mode).active)
	}

	@Test
	fun decodesHwcap2() {
		assertTrue(MemoryProtection.decodeHwcap2(1L shl 18))
		assertFalse(MemoryProtection.decodeHwcap2((1L shl 18).inv()))
	}

	@Test
	fun describeNeverClaimsOnWhenUnknown() {
		val s = MemoryProtection.describe(MemoryProtection.MteStatus(true, MteMode.UNKNOWN))
		assertEquals("MTE status unknown", s)
	}
}
