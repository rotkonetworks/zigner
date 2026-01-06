package net.rotko.zigner.screens.keysetdetails.items

import android.content.res.Configuration
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.Icon
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalInspectionMode
import androidx.compose.ui.res.dimensionResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import net.rotko.zigner.R
import net.rotko.zigner.components.networkicon.IdentIconImage
import net.rotko.zigner.components.qrcode.AnimatedQrKeysInfo
import net.rotko.zigner.components.qrcode.EmptyAnimatedQrKeysProvider
import net.rotko.zigner.domain.BASE58_STYLE_ABBREVIATE
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.KeyModel
import net.rotko.zigner.domain.abbreviateString
import net.rotko.zigner.screens.keysetdetails.export.KeySetDetailsExportService
import net.rotko.zigner.ui.helpers.PreviewData
import net.rotko.zigner.ui.theme.SignerNewTheme
import net.rotko.zigner.ui.theme.SignerTypeface
import net.rotko.zigner.ui.theme.fill12
import net.rotko.zigner.ui.theme.textSecondary
import net.rotko.zigner.ui.theme.textTertiary


@Composable
fun SeedKeyDetails(
	model: KeyModel,
	onShowRoot: Callback,
	onSeedSelect: Callback,
	modifier: Modifier = Modifier,
) {
	val plateShape = RoundedCornerShape(dimensionResource(id = R.dimen.qrShapeCornerRadius))

	Column(
		modifier = modifier
			.fillMaxWidth(),
		horizontalAlignment = Alignment.CenterHorizontally,
	) {
		// FVK QR Code - shown automatically, no extra tap needed
		Box(
			modifier = Modifier
				.padding(horizontal = 16.dp, vertical = 8.dp)
				.fillMaxWidth()
				.aspectRatio(1f)
				.clip(plateShape)
				.background(Color.White, plateShape),
			contentAlignment = Alignment.Center,
		) {
			if (LocalInspectionMode.current) {
				AnimatedQrKeysInfo(
					input = Unit,
					provider = EmptyAnimatedQrKeysProvider(),
					modifier = Modifier.padding(8.dp)
				)
			} else {
				AnimatedQrKeysInfo(
					input = KeySetDetailsExportService.GetQrCodesListRequest(
						seedName = model.seedName,
						keys = emptyList()
					),
					provider = KeySetDetailsExportService(),
					modifier = Modifier.padding(8.dp)
				)
			}
		}

		// Identicon and name below QR
		Row(
			modifier = Modifier
				.padding(top = 12.dp)
				.clickable(onClick = onSeedSelect),
			verticalAlignment = Alignment.CenterVertically,
		) {
			IdentIconImage(
				identicon = model.identicon,
				modifier = Modifier.padding(end = 8.dp),
				size = 32.dp
			)
			Text(
				text = model.seedName,
				color = MaterialTheme.colors.primary,
				style = SignerTypeface.TitleL,
				textAlign = TextAlign.Center
			)
			Spacer(modifier = Modifier.padding(horizontal = 2.dp))
			Icon(
				imageVector = Icons.Default.KeyboardArrowDown,
				modifier = Modifier.size(24.dp),
				contentDescription = stringResource(R.string.description_expand_button),
				tint = MaterialTheme.colors.textSecondary
			)
		}

		// Base58 address
		Text(
			model.base58.abbreviateString(BASE58_STYLE_ABBREVIATE),
			color = MaterialTheme.colors.textTertiary,
			style = SignerTypeface.BodyM,
			maxLines = 1,
			modifier = Modifier
				.padding(top = 8.dp)
				.clickable(onClick = onShowRoot)
				.background(
					MaterialTheme.colors.fill12,
					RoundedCornerShape(dimensionResource(id = R.dimen.innerFramesCornerRadius))
				)
				.padding(horizontal = 16.dp, vertical = 4.dp)
		)
	}
}


@Preview(
	name = "light",
	uiMode = Configuration.UI_MODE_NIGHT_NO,
	showBackground = true,
)
@Preview(
	name = "dark",
	uiMode = Configuration.UI_MODE_NIGHT_YES,
	backgroundColor = 0xFFFFFFFF
)
@Composable
private fun PreviewKeySeedCard() {
	SignerNewTheme {
		SeedKeyDetails(KeyModel.createStub()
			.copy(identicon = PreviewData.Identicon.jdenticonIcon),
			{},
			{},
			)
	}
}
