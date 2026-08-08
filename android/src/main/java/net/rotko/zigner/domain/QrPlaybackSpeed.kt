package net.rotko.zigner.domain

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Global animated-QR playback speed, shared by every multipart QR display on
 * the device (PCZT sign / signature, note-sync, FROST, module responses...).
 *
 * ONE preference is the right model: the throughput bottleneck is the same
 * camera/display pair regardless of which flow rendered the QR, so a speed the
 * user finds readable for note-sync applies equally to signing.
 *
 * Persisted in application-scoped SharedPreferences so it survives reboots.
 * Range spans the two historical extremes the codebase hardcoded:
 *   60ms  (~16 fps)  — fast, for cameras/phones that lock instantly
 *   700ms (~1.4 fps) — the old PCZT safety floor for macro-less webcams
 */
object QrPlaybackSpeed {
	const val MIN_DELAY_MS = 60
	const val MAX_DELAY_MS = 700
	const val DEFAULT_DELAY_MS = 350

	private const val PREFS_NAME = "qr_playback_speed"
	private const val KEY_DELAY_MS = "delay_ms"

	private val _delayMs = MutableStateFlow(DEFAULT_DELAY_MS)

	/** Current milliseconds per frame; composables collect this for live updates. */
	val delayMs: StateFlow<Int> = _delayMs

	@Volatile
	private var prefs: SharedPreferences? = null

	/** Load the persisted speed (idempotent). Call from any composable's LaunchedEffect. */
	fun init(context: Context) {
		if (prefs != null) return
		val p = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
		prefs = p
		_delayMs.value = p.getInt(KEY_DELAY_MS, DEFAULT_DELAY_MS)
	}

	/** Update the speed live and persist it. */
	fun set(delayMs: Int, context: Context) {
		val clamped = delayMs.coerceIn(MIN_DELAY_MS, MAX_DELAY_MS)
		_delayMs.value = clamped
		val p = prefs
			?: context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
				.also { prefs = it }
		p.edit().putInt(KEY_DELAY_MS, clamped).apply()
	}
}
