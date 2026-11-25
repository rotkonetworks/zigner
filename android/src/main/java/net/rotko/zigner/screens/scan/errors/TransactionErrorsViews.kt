package net.rotko.zigner.screens.scan.errors

import android.content.Context
import androidx.compose.ui.graphics.RectangleShape
import android.content.res.Configuration
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.dimensionResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.*
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import net.rotko.zigner.R
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*

const val COMPOSE_URL_TAG_ANNOTATION = "URL"

/**
 * Bottom sheet created to show Transaction errors in scan flow,
 * but used to show errors in a bottoms sheets in other places as well
 */
@Composable
fun LocalErrorBottomSheet(
	error: LocalErrorSheetModel,
	onOk: Callback
) {
	Column(
		Modifier
			.fillMaxWidth(1f)
			.verticalScroll(rememberScrollState())
	) {
		Text(
			text = error.title,
			color = MaterialTheme.colors.primary,
			style = SignerTypeface.TitleM,
			modifier = Modifier.padding(
				top = 32.dp,
				bottom = 8.dp,
				start = 32.dp,
				end = 32.dp
			),
		)
		Text(
			text = error.subtitle,
			color = MaterialTheme.colors.textSecondary,
			style = SignerTypeface.BodyM,
			modifier = Modifier
				.padding(horizontal = 32.dp)
				.padding(bottom = 16.dp),
		)

		if (error.description != null) {
			Column(
				modifier = Modifier
					.fillMaxWidth(1f)
					.padding(horizontal = 24.dp)
					.background(
						MaterialTheme.colors.fill6,
						RectangleShape
					)
					.border(
						1.dp,
						MaterialTheme.colors.fill12,
						RectangleShape
					)
			) {
				Text(
					text = error.description,
					color = MaterialTheme.colors.primary,
					style = SignerTypeface.BodyL,
					modifier = Modifier.padding(16.dp)
				)
			}
		}
		SecondaryButtonWide(
			label = stringResource(id = R.string.generic_ok),
			modifier = Modifier.padding(24.dp),
			withBackground = true,
			onClicked = onOk,
		)
	}
}

data class LocalErrorSheetModel(
	val title: String,
	val subtitle: String,
	val description: String? = null,
) {
	constructor(
		context: Context,
		details: String,
	) : this(
		title = context.getString(R.string.transaction_generic_error_title),
		subtitle = context.getString(R.string.transaction_generic_error_description),
		description = details
	)
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
private fun PreviewTransactionErrorBottomSheet() {
	SignerNewTheme {
		val model = LocalErrorSheetModel(
			title = "Something went wrong",
			subtitle = "The code could not be read.",
		)
		LocalErrorBottomSheet(
			error = model, onOk = {}
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
private fun PreviewTransactionErrorBottomSheetCustom() {
	SignerNewTheme {
		val context = LocalContext.current
		val model =
			LocalErrorSheetModel(
				context = context,
				details = "Bad input data. Metadata for westend9330 is already in the database."
			)
		LocalErrorBottomSheet(
			error = model, onOk = {}
		)
	}
}
