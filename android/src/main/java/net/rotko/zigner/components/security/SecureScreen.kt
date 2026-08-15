package net.rotko.zigner.components.security

import android.app.Activity
import android.view.WindowManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalContext

/**
 * Marks the window secure while a composable showing SECRET material is on
 * screen: no screenshots, no screen recording, no thumbnail in the recents
 * switcher, and no capture by an accessibility or casting service.
 *
 * The recents thumbnail is the one people forget. Android snapshots the window
 * when the app is backgrounded, and that snapshot outlives the screen - so a
 * seed phrase can sit in the task switcher long after the user has moved on.
 *
 * Applied per-screen rather than to the whole app on purpose. Blanket
 * FLAG_SECURE would also cover the QR codes this device exists to display -
 * release public keys, signatures, signed transactions - all of which are
 * public by construction and which an operator has good reason to capture and
 * send to someone. Protecting those costs usability and buys nothing, and a
 * mitigation that gets in the way of legitimate work is one people route
 * around.
 */
@Composable
fun SecureScreen() {
	val context = LocalContext.current
	DisposableEffect(context) {
		val window = (context as? Activity)?.window
		window?.setFlags(
			WindowManager.LayoutParams.FLAG_SECURE,
			WindowManager.LayoutParams.FLAG_SECURE,
		)
		onDispose {
			// Cleared on the way out so the flag tracks the screen showing the
			// secret, not the lifetime of the process.
			window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
		}
	}
}
