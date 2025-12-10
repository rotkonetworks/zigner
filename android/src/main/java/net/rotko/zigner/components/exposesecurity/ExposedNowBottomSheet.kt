package net.rotko.zigner.components.exposesecurity

import android.content.res.Configuration.UI_MODE_NIGHT_NO
import android.content.res.Configuration.UI_MODE_NIGHT_YES
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import net.rotko.zigner.R
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.SignerNewTheme
import net.rotko.zigner.ui.theme.SignerTypeface
import net.rotko.zigner.ui.theme.red400
import net.rotko.zigner.ui.theme.textSecondary

@Composable
internal fun ExposedNowBottomSheet(
	close: Callback,
) {
	Column(
		modifier = Modifier
			.fillMaxWidth(),
		horizontalAlignment = Alignment.CenterHorizontally,
	) {

		Image(
			painter = painterResource(id = R.drawable.ic_shield_exposed_32),
			contentDescription = stringResource(R.string.description_shield_exposed_icon),
			colorFilter = ColorFilter.tint(MaterialTheme.colors.red400),
			modifier = Modifier
				.padding(vertical = 24.dp)
				.size(80.dp),
		)

		Text(
			text = stringResource(R.string.exposed_now_title),
			color = MaterialTheme.colors.primary,
			style = SignerTypeface.TitleL,
			modifier = Modifier
				.fillMaxWidth(1f)
				.padding(horizontal = 24.dp),
		)
		Spacer(modifier = Modifier.padding(top = 16.dp))
		Text(
			text = stringResource(R.string.exposed_now_message),
			color = MaterialTheme.colors.textSecondary,
			style = SignerTypeface.BodyL,
			modifier = Modifier
				.fillMaxWidth(1f)
				.padding(horizontal = 24.dp),

			)

		SecondaryButtonWide(
			label = stringResource(R.string.general_got_it),
			modifier = Modifier.padding(horizontal = 32.dp, vertical = 24.dp),
			withBackground = true,
		) {
			close()
		}
	}
}


@Preview(
	name = "light", group = "themes", uiMode = UI_MODE_NIGHT_NO,
	showBackground = true, backgroundColor = 0xFFFFFFFF,
)
@Preview(
	name = "dark", group = "themes", uiMode = UI_MODE_NIGHT_YES,
	showBackground = true, backgroundColor = 0xFF000000,
)
@Composable
private fun PreviewExposedNowBottomSheet() {
	SignerNewTheme {
		ExposedNowBottomSheet(
			{},
		)
	}
}

