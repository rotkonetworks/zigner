package net.rotko.zigner.screens.scan.bananasplitcreate.show

import android.content.res.Configuration
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalInspectionMode
import androidx.compose.ui.res.dimensionResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import net.rotko.zigner.R
import net.rotko.zigner.components.base.NotificationFrameText
import net.rotko.zigner.components.base.PrimaryButton
import net.rotko.zigner.components.base.ScreenHeaderClose
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.qrcode.EmptyQrCodeProvider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.getData
import net.rotko.zigner.domain.intoImageBitmap
import net.rotko.zigner.ui.helpers.PreviewData
import net.rotko.zigner.ui.theme.SignerNewTheme
import net.rotko.zigner.ui.theme.SignerTypeface
import net.rotko.zigner.ui.theme.textSecondary
import net.rotko.zigner.ui.theme.textTertiary
import io.parity.signer.uniffi.QrData


/**
 * Banana Split shards are INDEPENDENT secret shares: an M-of-N split only buys
 * anything if the shards live in DIFFERENT places. So each shard is shown as its
 * own static, capturable QR - "Shard i of N" with Prev/Next paging - never fused
 * into one animated stream (which would force capturing every shard in a single
 * session at one location, collapsing it back to a single-location backup).
 */
@Composable
fun BananaSplitExportScreen(
	qrCodes: List<QrData>,
	onMenu: Callback,
	onClose: Callback,
	modifier: Modifier = Modifier,
) {
	Column(modifier.fillMaxHeight(1f)) {
		ScreenHeaderClose(title = "", onClose = onClose, onMenu = onMenu)
		Column(
			modifier = Modifier
				.verticalScroll(rememberScrollState())
				.weight(weight = 1f, fill = false)
				.padding(start = 16.dp, end = 16.dp, bottom = 48.dp, top = 24.dp)
		) {
			if (LocalInspectionMode.current) {
				BananaSplitShardPager(
					shardImages = listOf(PreviewData.exampleQRData.intoImageBitmap()),
					modifier = Modifier.padding(8.dp),
				)
			} else {
				val shardImages = remember { mutableStateOf<List<ImageBitmap>>(emptyList()) }
				LaunchedEffect(key1 = qrCodes) {
					// One QR image per shard (each QrData is a single-frame payload).
					EmptyQrCodeProvider().getQrCodesList(qrCodes.map { it.getData() })
						?.images
						?.map { it.intoImageBitmap() }
						?.let { shardImages.value = it }
				}
				BananaSplitShardPager(
					shardImages = shardImages.value,
					modifier = Modifier.padding(8.dp),
				)
			}
			NotificationFrameText(message = stringResource(R.string.create_bs_export_notification_text))
		}
	}
}


/**
 * Pages through one shard image at a time. Each page is a static QR that can be
 * scanned or photographed on its own before moving to the next shard.
 */
@Composable
private fun BananaSplitShardPager(
	shardImages: List<ImageBitmap>,
	modifier: Modifier = Modifier,
) {
	val qrRounding = dimensionResource(id = R.dimen.qrShapeCornerRadius)
	var index by remember { mutableStateOf(0) }
	val total = shardImages.size
	val safeIndex = if (total == 0) 0 else index.coerceIn(0, total - 1)

	Column(modifier = modifier) {
		if (total > 0) {
			Text(
				text = stringResource(R.string.create_bs_shard_counter, safeIndex + 1, total),
				style = SignerTypeface.TitleS,
				color = MaterialTheme.colors.textSecondary,
				modifier = Modifier
					.fillMaxWidth()
					.padding(bottom = 8.dp),
			)
		}
		Box(
			modifier = Modifier
				.fillMaxWidth(1f)
				.aspectRatio(1f)
				.background(Color.White, RoundedCornerShape(qrRounding)),
			contentAlignment = Alignment.Center,
		) {
			shardImages.getOrNull(safeIndex)?.let { image ->
				Image(
					bitmap = image,
					contentDescription = stringResource(R.string.qr_with_address_to_scan_description),
					contentScale = ContentScale.Fit,
					modifier = Modifier.fillMaxSize(),
				)
			}
		}

		if (total > 1) {
			Row(
				modifier = Modifier
					.fillMaxWidth()
					.padding(top = 12.dp),
				horizontalArrangement = Arrangement.spacedBy(12.dp),
				verticalAlignment = Alignment.CenterVertically,
			) {
				SecondaryButtonWide(
					label = stringResource(R.string.create_bs_shard_prev),
					isEnabled = safeIndex > 0,
					withBackground = true,
					modifier = Modifier.weight(1f),
				) { if (safeIndex > 0) index = safeIndex - 1 }
				PrimaryButton(
					label = stringResource(R.string.create_bs_shard_next),
					isEnabled = safeIndex < total - 1,
					modifier = Modifier.weight(1f),
				) { if (safeIndex < total - 1) index = safeIndex + 1 }
			}
		}
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
private fun PreviewBananaSplitExportScreen() {
	SignerNewTheme {
		BananaSplitExportScreen(
			qrCodes = listOf(
				QrData.Regular(PreviewData.exampleQRData),
			),
			onClose = {},
			onMenu = {},
		)
	}
}
