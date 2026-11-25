package net.rotko.zigner.screens.settings.general

import android.content.res.Configuration
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Switch
import androidx.compose.material.SwitchDefaults
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.outlined.Article
import androidx.compose.material.icons.outlined.Groups
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.LightMode
import androidx.compose.material.icons.outlined.Policy
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.foundation.interaction.MutableInteractionSource
import android.os.SystemClock
import android.widget.Toast
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import androidx.navigation.compose.rememberNavController
import net.rotko.zigner.R
import net.rotko.zigner.components.base.ScreenHeaderClose
import net.rotko.zigner.components.exposesecurity.ExposedIcon
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.NetworkState
import net.rotko.zigner.ui.theme.SignerNewTheme
import net.rotko.zigner.ui.theme.SignerTypeface
import net.rotko.zigner.ui.theme.pink500
import net.rotko.zigner.ui.theme.red400
import net.rotko.zigner.ui.theme.textSecondary
import net.rotko.zigner.ui.theme.textTertiary


// Number of taps on the version line that reveals developer options.
private const val REVEAL_TAP_TARGET = 5
// Start showing the "N taps away" hint from this tap onwards (Android-style).
private const val REVEAL_TAP_HINT_AFTER = 2
// Taps must land within this window of each other or the counter resets.
private const val TAP_WINDOW_MS = 3_000L

// Mutable, non-recomposing holder for the tap gesture. Kept out of snapshot state
// on purpose: taps must not trigger recomposition, only accumulate.
private class RevealTapState {
	var count: Int = 0
	var lastTapMs: Long = 0L
}

/**
 * Hidden 5-tap gesture, styled after Android's "tap Build number 7 times"
 * developer-mode unlock. Tapping the version line 5 times within a short
 * window REVEALS the developer options. It does not enable anything on its
 * own - online mode stays off and still requires an explicit, authenticated
 * confirmation to turn on.
 */
@Composable
private fun rememberDeveloperOptionsTapGesture(
	developerOptionsRevealed: Boolean,
	onRevealDeveloperOptions: Callback,
): Callback {
	val context = LocalContext.current
	val tapState = remember { RevealTapState() }
	return {
		val now = SystemClock.elapsedRealtime()
		if (now - tapState.lastTapMs > TAP_WINDOW_MS) {
			tapState.count = 0
		}
		tapState.lastTapMs = now
		tapState.count += 1

		when {
			developerOptionsRevealed -> {
				// Already unlocked; silently ignore further taps.
			}
			tapState.count >= REVEAL_TAP_TARGET -> {
				tapState.count = 0
				onRevealDeveloperOptions()
				Toast.makeText(
					context,
					context.getString(R.string.developer_options_revealed_toast),
					Toast.LENGTH_LONG,
				).show()
			}
			tapState.count >= REVEAL_TAP_HINT_AFTER -> {
				val remaining = REVEAL_TAP_TARGET - tapState.count
				Toast.makeText(
					context,
					context.resources.getQuantityString(
						R.plurals.developer_options_countdown_toast,
						remaining,
						remaining,
					),
					Toast.LENGTH_SHORT,
				).show()
			}
		}
	}
}

@Composable
internal fun SettingsScreenGeneralView(
	navController: NavController,
	onShowTerms: Callback,
	onShowPrivacyPolicy: Callback,
	onBackup: Callback,
	onMultisigSettings: Callback,
	onReleaseKey: Callback,
	onAdvancedSettings: Callback,
	onExposedClicked: Callback,
	onLightThemeToggle: Callback,
	isLightThemeEnabled: Boolean,
	securitySummary: String,
	appVersion: String,
	networkState: State<NetworkState?>,
	developerOptionsRevealed: Boolean = false,
	onRevealDeveloperOptions: Callback = {},
) {
	val revealGesture = rememberDeveloperOptionsTapGesture(
		developerOptionsRevealed,
		onRevealDeveloperOptions,
	)
	Column(Modifier.background(MaterialTheme.colors.background)) {
		ScreenHeaderClose(
			title = stringResource(R.string.settings_title),
			onClose = { navController.popBackStack() },
		)
		Box(modifier = Modifier.weight(1f)) {
			Column(
				modifier = Modifier.verticalScroll(rememberScrollState()),
				verticalArrangement = Arrangement.spacedBy(2.dp)
			) {
				SettingsToggleElement(
					name = "Light Theme",
					description = "Black-on-white QR codes scan better on webcams",
					icon = Icons.Outlined.LightMode,
					isChecked = isLightThemeEnabled,
					onClick = onLightThemeToggle,
				)

				Spacer(modifier = Modifier.height(16.dp))

				SettingsElement(
					name = stringResource(R.string.settings_backup),
					icon = Icons.Outlined.Key,
					onClick = onBackup,
				)
				SettingsElement(
					name = "Multisig",
					icon = Icons.Outlined.Groups,
					onClick = onMultisigSettings,
				)
				SettingsElement(
					name = "Release key",
					icon = Icons.Outlined.Key,
					onClick = onReleaseKey,
				)
				SettingsElement(
					name = "Advanced Settings",
					icon = Icons.Outlined.Tune,
					onClick = onAdvancedSettings,
				)

				Spacer(modifier = Modifier.height(16.dp))
				SettingsElement(
					name = stringResource(R.string.documents_privacy_policy),
					icon = Icons.Outlined.Policy,
					onClick = onShowPrivacyPolicy
				)
				SettingsElement(
					name = stringResource(R.string.documents_terms_of_service),
					icon = Icons.Outlined.Article,
					onClick = onShowTerms
				)

				Spacer(modifier = Modifier.weight(1f))
				Spacer(modifier = Modifier.height(32.dp))
				Column(
					modifier = Modifier.fillMaxWidth(),
					horizontalAlignment = Alignment.CenterHorizontally
				) {
					Image(
						painter = painterResource(id = R.drawable.rotko_logo),
						contentDescription = "Zafu",
						modifier = Modifier.height(40.dp)
					)
					Spacer(modifier = Modifier.height(8.dp))
					Text(
						text = stringResource(R.string.settings_version, appVersion),
						style = SignerTypeface.BodyM,
						color = MaterialTheme.colors.textSecondary,
						modifier = Modifier.clickable(
							indication = null,
							interactionSource = remember { MutableInteractionSource() },
							onClick = revealGesture,
						),
					)
					Text(
						text = "Security: $securitySummary",
						style = SignerTypeface.CaptionM,
						color = MaterialTheme.colors.textTertiary,
					)
				}
				Spacer(modifier = Modifier.height(40.dp))
			}
			ExposedIcon(
				networkState = networkState,
				onClick = onExposedClicked,
				modifier = Modifier
					.align(Alignment.BottomEnd)
					.padding(end = 16.dp, bottom = 16.dp)
			)
		}
	}
}

@Composable
internal fun SettingsElement(
	name: String,
	icon: ImageVector? = null,
	isDanger: Boolean = false,
	skipChevron: Boolean = false,
	onClick: Callback,
) {
	Row(
		modifier = Modifier
			.fillMaxWidth()
			.clickable(onClick = onClick)
			.padding(vertical = 18.dp),
		verticalAlignment = Alignment.CenterVertically
	) {
		if (icon != null) {
			Image(
				imageVector = icon,
				contentDescription = null,
				colorFilter = ColorFilter.tint(
					if (isDanger) MaterialTheme.colors.red400 else MaterialTheme.colors.primary
				),
				modifier = Modifier
					.padding(start = 24.dp)
					.size(20.dp)
			)
			Text(
				text = name,
				style = SignerTypeface.TitleS,
				color = if (isDanger) MaterialTheme.colors.red400 else MaterialTheme.colors.primary,
				modifier = Modifier
					.padding(start = 12.dp)
					.weight(1f)
			)
		} else {
			Text(
				text = name,
				style = SignerTypeface.TitleS,
				color = if (isDanger) MaterialTheme.colors.red400 else MaterialTheme.colors.primary,
				modifier = Modifier
					.padding(start = 24.dp)
					.weight(1f)
			)
		}
		if (!skipChevron) {
			Image(
				imageVector = Icons.Filled.ChevronRight,
				contentDescription = null,
				colorFilter = ColorFilter.tint(MaterialTheme.colors.textTertiary),
				modifier = Modifier.padding(horizontal = 16.dp)
			)
		}
	}
}

@Composable
internal fun SettingsToggleElement(
	name: String,
	description: String,
	icon: ImageVector? = null,
	isChecked: Boolean,
	showWarning: Boolean = false,
	onClick: Callback,
) {
	Row(
		modifier = Modifier
			.fillMaxWidth()
			.clickable(onClick = onClick)
			.padding(vertical = 13.dp),
		verticalAlignment = Alignment.CenterVertically,
	) {
		if (icon != null) {
			Image(
				imageVector = icon,
				contentDescription = null,
				colorFilter = ColorFilter.tint(MaterialTheme.colors.primary),
				modifier = Modifier
					.padding(start = 24.dp)
					.size(20.dp)
			)
		}
		Column(
			modifier = Modifier
				.padding(start = if (icon != null) 12.dp else 24.dp)
				.weight(1f)
		) {
			Text(
				text = name,
				style = SignerTypeface.TitleS,
				color = MaterialTheme.colors.primary,
			)
			Text(
				text = description,
				style = SignerTypeface.CaptionM,
				color = if (showWarning) MaterialTheme.colors.red400 else MaterialTheme.colors.textSecondary,
			)
		}
		Spacer(modifier = Modifier.width(8.dp))
		Switch(
			checked = isChecked,
			onCheckedChange = null, // Handle via row click for confirmation
			colors = SwitchDefaults.colors(
				checkedThumbColor = MaterialTheme.colors.pink500,
				checkedTrackColor = MaterialTheme.colors.pink500.copy(alpha = 0.5f),
			),
			modifier = Modifier.padding(end = 16.dp)
		)
	}
}

@Preview(
	name = "light", group = "general", uiMode = Configuration.UI_MODE_NIGHT_NO,
	showBackground = true, backgroundColor = 0xFFFFFFFF,
)
@Preview(
	name = "dark", group = "general",
	uiMode = Configuration.UI_MODE_NIGHT_YES,
	showBackground = true, backgroundColor = 0xFF000000,
)
@Composable
private fun PreviewSettingsScreen() {
	SignerNewTheme {
		val state = remember { mutableStateOf(NetworkState.Past) }
		SettingsScreenGeneralView(
			navController = rememberNavController(),
			onShowTerms = {},
			onShowPrivacyPolicy = {},
			onBackup = {},
			onMultisigSettings = {},
		onReleaseKey = {},
			onAdvancedSettings = {},
			onExposedClicked = {},
			onLightThemeToggle = {},
			isLightThemeEnabled = false,
			securitySummary = "StrongBox · MTE on (synchronous)",
			appVersion = "0.6.1",
			networkState = state,
		)
	}
}
