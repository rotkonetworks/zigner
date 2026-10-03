package net.rotko.zigner.domain.security

import net.rotko.zigner.domain.security.DeviceIntegrity.BootState
import net.rotko.zigner.domain.security.DeviceIntegrity.Report
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceIntegrityTest {

	private fun report(
		boot: BootState,
		deviceState: String? = null,
		su: List<String> = emptyList(),
		testKeys: Boolean = false,
	) = Report(boot, deviceState, su, testKeys)

	@Test
	fun parsesBootStates() {
		assertEquals(BootState.GREEN, DeviceIntegrity.parseBootState("green"))
		assertEquals(BootState.YELLOW, DeviceIntegrity.parseBootState(" YELLOW\n"))
		assertEquals(BootState.ORANGE, DeviceIntegrity.parseBootState("orange"))
		assertEquals(BootState.RED, DeviceIntegrity.parseBootState("red"))
		assertEquals(BootState.UNKNOWN, DeviceIntegrity.parseBootState(null))
		assertEquals(BootState.UNKNOWN, DeviceIntegrity.parseBootState(""))
	}

	// GrapheneOS boots yellow: locked bootloader, user-set verification key.
	// Flagging it would train exactly the users who did things right to
	// dismiss the screen.
	@Test
	fun yellowIsNotAFinding() {
		assertFalse(report(BootState.YELLOW, "locked").needsAttention)
		assertFalse(report(BootState.GREEN, "locked").needsAttention)
	}

	// Many OEM builds hide the property; a non-finding must not nag.
	@Test
	fun unknownAloneIsNotAFinding() {
		assertFalse(report(BootState.UNKNOWN).needsAttention)
	}

	@Test
	fun unlockedBootloaderIsAFindingFromEitherProperty() {
		assertTrue(report(BootState.ORANGE).needsAttention)
		// device_state can be readable when verifiedbootstate is not
		assertTrue(report(BootState.UNKNOWN, "unlocked").needsAttention)
	}

	@Test
	fun rootEvidenceAndTestKeysAreFindings() {
		assertTrue(report(BootState.GREEN, su = listOf("/system/xbin/su")).needsAttention)
		assertTrue(report(BootState.GREEN, testKeys = true).needsAttention)
		assertTrue(report(BootState.RED).needsAttention)
	}
}
