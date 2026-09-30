package net.rotko.zigner.domain

import android.app.Activity
import android.content.Context
import android.view.WindowManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import java.util.concurrent.atomic.AtomicInteger


@Composable
fun KeepScreenOn() {
	val currentView = LocalView.current
	DisposableEffect(Unit) {
		currentView.keepScreenOn = true
		onDispose {
			currentView.keepScreenOn = false
		}
	}
}


private fun Activity.disableScreenshots() {
	window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
}
private fun Activity.enableScreenshots() {
	window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
}

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
 *
 * We need a counter here since during navigation the new screen's disposable
 * effect starts before the old one's onDispose() runs (crossfade composes
 * both destinations at once). Without it, the flag would briefly clear while
 * the outgoing screen is still on top. Counting keeps screenshots forbidden
 * as long as any secret screen forbids them.
 */
@Composable
fun DisableScreenshots() {
	val context: Context = LocalContext.current
	DisposableEffect(Unit) {
		val count = DisableScreenshotCounter.forbiddenViews.incrementAndGet()
		reactOnCounter(count, context)
		onDispose {
			val counted = DisableScreenshotCounter.forbiddenViews.decrementAndGet()
			reactOnCounter(counted, context)
		}
	}
}

private fun reactOnCounter(counter: Int, context: Context) {
 if (counter > 0) {
	 context.findActivity()?.disableScreenshots()
 } else {
	 context.findActivity()?.enableScreenshots()
 }
}

private object DisableScreenshotCounter {
	var forbiddenViews = AtomicInteger(0)
}
