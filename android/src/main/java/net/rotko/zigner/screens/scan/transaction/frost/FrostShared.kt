package net.rotko.zigner.screens.scan.transaction.frost

import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.size
import androidx.compose.material.Icon
import androidx.compose.material.MaterialTheme
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import net.rotko.zigner.ui.theme.red400
import timber.log.Timber

/** Tap-to-toast warning triangle. Android equivalent of zafu's hover tooltip. */
@Composable
fun DontQuitIcon(message: String) {
	val ctx = LocalContext.current
	Icon(
		imageVector = Icons.Default.Warning,
		contentDescription = message,
		tint = MaterialTheme.colors.red400,
		modifier = Modifier
			.size(18.dp)
			.clickable { Toast.makeText(ctx, message, Toast.LENGTH_SHORT).show() }
	)
}

/** Split raw bytes into P-frame QR chunks zafu's AnimatedQrScanner expects.
 *  Frame format: `P<idx>/<total>/<urType>/<base64Chunk>` (chunkSize 400 = zafu default). */
fun toAnimatedQrFrames(raw: ByteArray, urType: String, chunkSize: Int = 400): List<List<UByte>>? = try {
	val b64 = android.util.Base64.encodeToString(raw, android.util.Base64.NO_WRAP)
	val total = ((b64.length + chunkSize - 1) / chunkSize).coerceAtLeast(1)
	Timber.d("[FROST] frames urType=$urType rawBytes=${raw.size} b64Len=${b64.length} total=$total")
	(0 until total).map { i ->
		val chunk = b64.substring(i * chunkSize, minOf((i + 1) * chunkSize, b64.length))
		"P${i + 1}/$total/$urType/$chunk".toByteArray(Charsets.UTF_8).map { it.toUByte() }
	}
} catch (e: Exception) {
	Timber.e(e, "[FROST] frame prep failed urType=$urType bytes=${raw.size}")
	null
}

/** UTF-8 string overload — JSON envelopes etc. */
fun toAnimatedQrFrames(payload: String, urType: String, chunkSize: Int = 400): List<List<UByte>>? =
	toAnimatedQrFrames(payload.toByteArray(Charsets.UTF_8), urType, chunkSize)

/** Decode a hex string to bytes; returns null if not even-length hex. */
fun hexToBytesOrNull(s: String): ByteArray? {
	if (s.length % 2 != 0 || !s.matches(Regex("^[0-9a-fA-F]+$"))) return null
	return ByteArray(s.length / 2) { i -> s.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
}
