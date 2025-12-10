package net.rotko.zigner.domain

import timber.log.Timber
import net.rotko.zigner.BuildConfig
import io.parity.signer.uniffi.ErrorDisplayed
import java.lang.RuntimeException

fun submitErrorState(message: String) {
	Timber.e("error state", message)
	if (BuildConfig.DEBUG) {
		throw RuntimeException(message)
	}
}


fun ErrorDisplayed.getDebugDetailedDescriptionString(): String {
	return this.javaClass.name + "Message: " + message
}

