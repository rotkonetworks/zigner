package net.rotko.zigner.domain

import android.content.Context
import timber.log.Timber
import android.widget.Toast
import net.rotko.zigner.R
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.backend.OperationResult
import net.rotko.zigner.screens.scan.errors.findErrorDisplayed
import io.parity.signer.uniffi.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext


interface Navigator {
	/**
	 * For old Rust-backed navigation actions
	 */
	fun navigate(
		action: Action,
		details: String = "",
		seedPhrase: String = ""
	)

	fun backAction()
}


class EmptyNavigator : Navigator {
	override fun navigate(action: Action, details: String, seedPhrase: String) {
		//do nothing
	}

	override fun backAction() {
	}
}

class FakeNavigator : Navigator {
	override fun navigate(action: Action, details: String, seedPhrase: String) {
		try {
			backendAction(action, details, seedPhrase)
		} catch (e: ErrorDisplayed) {
			Timber.e("fake navigation error", e.message ?: e.toString())
		}
		//do nothing with result
	}

	override fun backAction() {
		navigate(Action.GO_BACK)
	}
}

data class NavigationError(val message: String)
