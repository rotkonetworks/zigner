package net.rotko.zigner.screens.settings.frost

import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.Icon
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Check
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import net.rotko.zigner.ui.theme.SignerTypeface
import net.rotko.zigner.ui.theme.accentGreen

/** Square icon-only button with a long-press → Toast tooltip explaining the action.
 *  Used for compact wallet-row actions where icons replace text labels. */
@Composable
internal fun IconActionButton(
	icon: ImageVector,
	label: String,
	onClick: () -> Unit,
	modifier: Modifier = Modifier,
	tint: Color = MaterialTheme.colors.primary,
	background: Color = MaterialTheme.colors.surface,
) {
	val ctx = LocalContext.current
	Box(
		modifier = modifier
			.clip(RoundedCornerShape(8.dp))
			.background(background)
			.pointerInput(label) {
				detectTapGestures(
					onTap = { onClick() },
					onLongPress = { Toast.makeText(ctx, label, Toast.LENGTH_SHORT).show() },
				)
			}
			.padding(vertical = 10.dp),
		contentAlignment = Alignment.Center,
	) {
		Icon(
			imageVector = icon,
			contentDescription = label,
			tint = tint,
			modifier = Modifier.size(20.dp),
		)
	}
}

/** Animated success state — scale+fade-in checkmark in a circular badge,
 *  with a label below. Drop into any column, gate visibility with
 *  AnimatedVisibility for a clean entrance. */
@Composable
internal fun AnimatedSuccessBadge(
	visible: Boolean,
	message: String,
	modifier: Modifier = Modifier,
) {
	// Start the transition from `false` so the entrance animation actually plays
	// when the parent composes us with visible=true (AnimatedVisibility otherwise
	// skips the enter animation if its initial visible value is true).
	val transitionState = remember { MutableTransitionState(false) }
	transitionState.targetState = visible
	AnimatedVisibility(
		visibleState = transitionState,
		enter = scaleIn(
			initialScale = 0.4f,
			animationSpec = spring(
				dampingRatio = Spring.DampingRatioMediumBouncy,
				stiffness = Spring.StiffnessMediumLow,
			),
		) + fadeIn(animationSpec = tween(200)),
		exit = scaleOut(targetScale = 0.8f, animationSpec = tween(200)) + fadeOut(animationSpec = tween(200)),
		modifier = modifier,
	) {
		Column(
			horizontalAlignment = Alignment.CenterHorizontally,
			verticalArrangement = Arrangement.spacedBy(12.dp),
		) {
			Box(
				modifier = Modifier
					.size(72.dp)
					.clip(CircleShape)
					.background(MaterialTheme.colors.accentGreen.copy(alpha = 0.15f)),
				contentAlignment = Alignment.Center,
			) {
				Icon(
					imageVector = Icons.Outlined.Check,
					contentDescription = null,
					tint = MaterialTheme.colors.accentGreen,
					modifier = Modifier.size(40.dp),
				)
			}
			Text(
				text = message,
				style = SignerTypeface.TitleS,
				color = MaterialTheme.colors.accentGreen,
			)
		}
	}
}
