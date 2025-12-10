package net.rotko.zigner.components

import androidx.compose.material.Icon
import androidx.compose.material.MaterialTheme
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import net.rotko.zigner.domain.NetworkState
import net.rotko.zigner.ui.theme.Crypto400
import net.rotko.zigner.ui.theme.SignalDanger
import net.rotko.zigner.ui.theme.SignalWarning

@Composable
fun NavbarShield(networkState: State<NetworkState?>) {

	when (networkState.value) {
		NetworkState.None -> Icon(
			Icons.Default.GppGood,
			"device is safe",
			tint = MaterialTheme.colors.Crypto400
		)
		NetworkState.Active -> Icon(
			Icons.Default.GppBad,
			"device is online",
			tint = MaterialTheme.colors.SignalDanger
		)
		NetworkState.Past -> Icon(
			Icons.Default.GppBad,
			"potential security breach",
			tint = MaterialTheme.colors.SignalWarning
		)
		null -> Icon(
			Icons.Default.GppMaybe,
			"Safety indicator error",
			tint = MaterialTheme.colors.SignalDanger
		)
	}
}
