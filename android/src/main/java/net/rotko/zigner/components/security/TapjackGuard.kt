package net.rotko.zigner.components.security

import android.app.Activity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalContext

/**
 * Discards touches that arrive while another app's window is drawn over this
 * one, for the duration of an approval screen.
 *
 * The attack is tapjacking: an overlay covers what you are agreeing to while
 * leaving the approve button exposed, so you read one thing and authorise
 * another. That is a generic Android nuisance for most apps and a direct
 * attack on this one, because "the device shows you what you are signing" is
 * the property everything else here rests on. An overlay breaks it without
 * touching a single line of our code.
 *
 * Scoped to approval screens rather than set app-wide, and this is a real
 * trade rather than caution. The flag rejects touches whenever ANY overlay is
 * present, including benign ones - blue-light filters, screen dimmers,
 * floating utilities. App-wide, that makes the whole app unusable for those
 * users and they uninstall or work around it. Scoped, it costs them only the
 * approval step, which is exactly the step worth being strict about.
 */
@Composable
fun TapjackGuard() {
	val context = LocalContext.current
	DisposableEffect(context) {
		val root = (context as? Activity)?.window?.decorView
		val previous = root?.filterTouchesWhenObscured ?: false
		root?.filterTouchesWhenObscured = true
		onDispose { root?.filterTouchesWhenObscured = previous }
	}
}
