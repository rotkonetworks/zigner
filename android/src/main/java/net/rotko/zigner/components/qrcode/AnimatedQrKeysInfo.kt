package net.rotko.zigner.components.qrcode

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Slider
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.dimensionResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import net.rotko.zigner.R
import net.rotko.zigner.domain.QrPlaybackSpeed
import net.rotko.zigner.domain.intoImageBitmap
import net.rotko.zigner.ui.helpers.PreviewData
import net.rotko.zigner.ui.theme.*
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.milliseconds

/**
 * Animated multipart QR. Cycles frames at the user's preferred playback speed
 * ([QrPlaybackSpeed], adjustable live via [QrPlaybackSpeedSlider], shown for
 * multipart payloads). Single-frame QRs render statically with no slider.
 */
@OptIn(ExperimentalUnsignedTypes::class)
@Composable
fun <T> AnimatedQrKeysInfo(
	input: T,
	provider: AnimatedQrKeysProvider<T>,
	modifier: Modifier = Modifier,
	showSpeedControl: Boolean = true,
) {
	val qrRounding = dimensionResource(id = R.dimen.qrShapeCornerRadius)
	val context = LocalContext.current
	LaunchedEffect(Unit) { QrPlaybackSpeed.init(context.applicationContext) }
	val qrCodes = remember { mutableStateOf<List<ImageBitmap>>(emptyList()) }
	val currentCode = remember { mutableStateOf<ImageBitmap?>(null) }

	Column(modifier = modifier) {
		Box(
			modifier = Modifier
				.fillMaxWidth(1f)
				.aspectRatio(1f)
				.background(
					Color.White,
					RoundedCornerShape(qrRounding)
				),
			contentAlignment = Alignment.Center,
		) {
			currentCode.value?.let { currentImage ->
				Image(
					bitmap = currentImage,
					contentDescription = stringResource(R.string.qr_with_address_to_scan_description),
					contentScale = ContentScale.Fit,
					modifier = Modifier.fillMaxSize()
				)
			}
		}

		if (showSpeedControl && qrCodes.value.size > 1) {
			QrPlaybackSpeedSlider()
		}
	}

	LaunchedEffect(key1 = input) {
		provider.getQrCodesList(input)
			?.images
			?.map { it.intoImageBitmap() }
			?.let { qrCodes.value = it }
	}

	LaunchedEffect(key1 = qrCodes.value) {
		if (qrCodes.value.isEmpty()) return@LaunchedEffect
		var index = 0
		while (true) {
			currentCode.value = qrCodes.value[index]
			index = (index + 1) % qrCodes.value.size
			// live: recompute each iteration so dragging the slider takes effect
			// without restarting the loop
			delay(QrPlaybackSpeed.delayMs.value.milliseconds)
		}
	}
}

/**
 * Shared "QR speed" slider, also used directly by the dedicated PCZT/module
 * screens that animate frames manually. Persists via [QrPlaybackSpeed].
 */
@Composable
internal fun QrPlaybackSpeedSlider(modifier: Modifier = Modifier) {
	val context = LocalContext.current
	LaunchedEffect(Unit) { QrPlaybackSpeed.init(context.applicationContext) }
	val delayMs by QrPlaybackSpeed.delayMs.collectAsState()
	val fps = if (delayMs > 0) ((1000.0 / delayMs) + 0.5).toInt() else 0

	Column(
		modifier = modifier
			.fillMaxWidth()
			.padding(top = 12.dp),
		verticalArrangement = Arrangement.spacedBy(4.dp),
	) {
		Row(
			modifier = Modifier.fillMaxWidth(),
			horizontalArrangement = Arrangement.SpaceBetween,
			verticalAlignment = Alignment.CenterVertically,
		) {
			Text(
				text = "QR speed",
				style = SignerTypeface.CaptionM,
				color = MaterialTheme.colors.textTertiary,
			)
			Text(
				text = "$fps fps",
				style = SignerTypeface.CaptionM,
				color = MaterialTheme.colors.textSecondary,
			)
		}
		Slider(
			value = delayMs.toFloat(),
			onValueChange = { QrPlaybackSpeed.set(it.toInt(), context) },
			valueRange = QrPlaybackSpeed.MIN_DELAY_MS.toFloat()..QrPlaybackSpeed.MAX_DELAY_MS.toFloat(),
			modifier = Modifier.fillMaxWidth(),
		)
	}
}

data class AnimatedQrImages(val images: List<List<UByte>>)

interface AnimatedQrKeysProvider<T> {
	suspend fun getQrCodesList(input: T): AnimatedQrImages?
}

class EmptyAnimatedQrKeysProvider : AnimatedQrKeysProvider<Any> {
	override suspend fun getQrCodesList(input: Any): AnimatedQrImages {
		return AnimatedQrImages(listOf(PreviewData.exampleQRData))
	}
}
