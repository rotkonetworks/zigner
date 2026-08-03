package net.rotko.zigner.domain.module

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host-side guard for the turnstile module dispatch predicate.
 *
 * The wallet (zafu) animates a turnstile migration as the prelude envelope
 * [0x53][0x04][0x03] || redacted_v6_pczt (see fixb-envelope-spec). The device
 * MUST route exactly this prelude (and the batch form 0x04) to the wasm
 * protocol module, and MUST NOT confuse it with the legacy zcash-simple
 * (0x53 0x04 0x02) or penumbra/cosmos preludes. `isPcztPayload` is the seam
 * that makes that call; these assertions freeze the wire bytes.
 */
class ProtocolModulePreludeTest {

	private fun bytes(vararg b: Int): ByteArray =
		ByteArray(b.size) { i -> b[i].toByte() }

	@Test
	fun accepts_single_pczt_prelude() {
		// [0x53][0x04][0x03] || >=1 payload byte
		assertTrue(ProtocolModule.isPcztPayload(bytes(0x53, 0x04, 0x03, 0xAB)))
	}

	@Test
	fun accepts_batch_pczt_prelude() {
		// [0x53][0x04][0x04] batch form
		assertTrue(ProtocolModule.isPcztPayload(bytes(0x53, 0x04, 0x04, 0xAB)))
	}

	@Test
	fun rejects_zcash_simple_prelude() {
		// 0x53 0x04 0x02 is the built-in zcash-simple sign path, NOT the module.
		assertFalse(ProtocolModule.isPcztPayload(bytes(0x53, 0x04, 0x02, 0xAB)))
	}

	@Test
	fun rejects_non_zcash_crypto_byte() {
		// crypto byte must be 0x04 (Zcash); 0x03 (penumbra) is a different path.
		assertFalse(ProtocolModule.isPcztPayload(bytes(0x53, 0x03, 0x03, 0xAB)))
	}

	@Test
	fun rejects_empty_body() {
		// prelude alone (no pczt bytes) is not a signable request.
		assertFalse(ProtocolModule.isPcztPayload(bytes(0x53, 0x04, 0x03)))
	}

	@Test
	fun rejects_too_short() {
		assertFalse(ProtocolModule.isPcztPayload(bytes(0x53, 0x04)))
		assertFalse(ProtocolModule.isPcztPayload(ByteArray(0)))
	}
}
