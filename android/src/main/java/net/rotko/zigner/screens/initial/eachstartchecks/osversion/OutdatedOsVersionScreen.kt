package net.rotko.zigner.screens.initial.eachstartchecks.osversion

import android.content.res.Configuration
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.SecurityUpdate
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import net.rotko.zigner.R
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.SignerNewTheme
import net.rotko.zigner.ui.theme.SignerTypeface
import net.rotko.zigner.ui.theme.pink500
import net.rotko.zigner.ui.theme.textTertiary

@Composable
fun OutdatedOsVersionScreen(
	exposedVulnarabilities: List<KnownOSIssue>,
	onProceed: Callback
) {
	Column(
		modifier = Modifier
			.padding(24.dp)
	) {
		Spacer(Modifier.weight(0.5f))
		Column(
			modifier = Modifier
				.verticalScroll(rememberScrollState())
		) {
			Image(
				imageVector = Icons.Outlined.SecurityUpdate,
				contentDescription = null,
				colorFilter = ColorFilter.tint(MaterialTheme.colors.pink500),
				modifier = Modifier
					.padding(horizontal = 8.dp)
					.size(80.dp)
					.align(Alignment.CenterHorizontally)
			)
			Spacer(modifier = Modifier.padding(top = 16.dp))
			Text(
				modifier = Modifier
					.fillMaxWidth(1f),
				text = stringResource(R.string.initial_screen_outdated_os_title),
				color = MaterialTheme.colors.primary,
				style = SignerTypeface.TitleL,
				textAlign = TextAlign.Center,
			)
			Spacer(modifier = Modifier.padding(top = 16.dp))
			Text(
				modifier = Modifier
					.fillMaxWidth(1f),
				text = stringResource(
					R.string.initial_screen_outdated_os_description,
					exposedVulnarabilities.joinToString(", ") { it.toString() }
				),
				color = MaterialTheme.colors.textTertiary,
				style = SignerTypeface.BodyL,
				textAlign = TextAlign.Center,
			)
			Spacer(modifier = Modifier.padding(top = 24.dp))

			Spacer(modifier = Modifier.padding(top = 8.dp))
			PrimaryButtonWide(
				modifier = Modifier.padding(vertical = 24.dp),
				label = stringResource(R.string.onboarding_skip),
				onClicked = onProceed,
			)
		}
		Spacer(Modifier.weight(0.5f))
	}
}


@Preview(
	name = "light", group = "themes", uiMode = Configuration.UI_MODE_NIGHT_NO,
	showBackground = true, backgroundColor = 0xFFFFFFFF,
)
@Preview(
	name = "dark", group = "themes", uiMode = Configuration.UI_MODE_NIGHT_YES,
	showBackground = true, backgroundColor = 0xFF000000,
)
@Composable
private fun WrongOsVersionNotificationScreenPreview() {
	Box(modifier = Modifier.fillMaxSize()) {
		SignerNewTheme() {
			OutdatedOsVersionScreen(
				listOf(KnownOSIssue.CVE_2022_20465),
				onProceed = {},
			)
		}
	}
}


