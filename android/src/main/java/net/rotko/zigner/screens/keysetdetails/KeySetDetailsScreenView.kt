package net.rotko.zigner.screens.keysetdetails

import android.content.res.Configuration
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.Icon
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Surface
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.MoreHoriz
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.draw.clip
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.res.dimensionResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import androidx.navigation.compose.rememberNavController
import io.parity.signer.uniffi.FrostWalletSummaryFfi
import io.parity.signer.uniffi.frostListWallets
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.rotko.zigner.R
import net.rotko.zigner.components.base.ScanIconComponent
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.base.SettingsIcon
import net.rotko.zigner.components.exposesecurity.ExposedIcon
import net.rotko.zigner.domain.BASE58_STYLE_ABBREVIATE
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.domain.KeyModel
import net.rotko.zigner.domain.KeySetDetailsModel
import net.rotko.zigner.domain.NetworkState
import net.rotko.zigner.domain.abbreviateString
import net.rotko.zigner.domain.conditional
import net.rotko.zigner.screens.keysetdetails.items.HotWalletQrSection
import net.rotko.zigner.screens.keysetdetails.items.KeyDerivedItem
import net.rotko.zigner.screens.keysetdetails.items.SeedKeyDetails
import net.rotko.zigner.ui.mainnavigation.CoreUnlockedNavSubgraph
import net.rotko.zigner.ui.theme.SignerNewTheme
import net.rotko.zigner.ui.theme.SignerTypeface
import net.rotko.zigner.ui.theme.fill6
import net.rotko.zigner.ui.theme.pink300
import net.rotko.zigner.ui.theme.textDisabled
import net.rotko.zigner.ui.theme.textSecondary
import net.rotko.zigner.ui.theme.textTertiary

/**
 * Single Seed/Key set is selected is it's details
 * For non-multiselect state,
 * For multiselec screen KeyManager is still used
 */
@Composable
fun KeySetDetailsScreenView(
	model: KeySetDetailsModel,
	navController: NavController,
	networkState: State<NetworkState?>, //for shield icon
	fullModelWasEmpty: Boolean,
	onExposedClicked: Callback,
	onFilterClicked: Callback,
	onMenu: Callback,
	onSeedSelect: Callback,
	onAddNewDerivation: Callback,
	onShowRoot: Callback,
	onOpenKey: (keyAddr: String, keySpecs: String) -> Unit,
	getSeedPhrase: suspend (String) -> String? = { null },
) {
	Column {
		KeySetDetailsHeader(
			onAddKey = onAddNewDerivation,
			onSettings = {
				navController.navigate(CoreUnlockedNavSubgraph.settings)
			},
			onMenu = onMenu,
		)
		Box(modifier = Modifier.weight(1f)) {
			if (model.keysAndNetwork.isNotEmpty()) {
				Column(
					modifier = Modifier
						.verticalScroll(rememberScrollState()),
					verticalArrangement = Arrangement.spacedBy(4.dp),
				) {
					SeedKeyItemElement(
						model = model,
						onSeedSelect = onSeedSelect,
						onShowRoot = onShowRoot
					)

					HotWalletQrSection(
						seedName = model.root.seedName,
						getSeedPhrase = getSeedPhrase,
					)

					FilterRow(onFilterClicked)

					for (networkAndKeys in model.keysAndNetwork) {
						KeyDerivedItem(
							model = networkAndKeys.key,
							networkLogo = networkAndKeys.network.networkLogo,
						) {
							onOpenKey(
								networkAndKeys.key.addressKey,
								networkAndKeys.network.networkSpecsKey
							)
						}
					}

					MultisigSection(
						onManage = {
							navController.navigate(CoreUnlockedNavSubgraph.frostWalletList)
						},
					)
				}
			} else if (fullModelWasEmpty) {
				//no derived keys at all
				Column() {
					//seed
					SeedKeyItemElement(
						model = model,
						onSeedSelect = onSeedSelect,
						onShowRoot = onShowRoot
					)
					KeySetDetailsEmptyList(onAdd = onAddNewDerivation)
					MultisigSection(
						onManage = {
							navController.navigate(CoreUnlockedNavSubgraph.frostWalletList)
						},
					)
				}
			} else {
				//nothing to show but filter enabled
				Column() {
					SeedKeyItemElement(
						model = model,
						onSeedSelect = onSeedSelect,
						onShowRoot = onShowRoot
					)          //no keys because filtered
					FilterRow(onFilterClicked)
					Spacer(modifier = Modifier.weight(0.5f))
					Text(
						text = stringResource(R.string.key_set_details_all_filtered_keys_title),
						color = MaterialTheme.colors.primary,
						style = SignerTypeface.TitleM,
						textAlign = TextAlign.Center,
						modifier = Modifier.padding(horizontal = 40.dp)
					)
					Spacer(modifier = Modifier.weight(0.5f))
				}
			}

			ExposedIcon(
				networkState = networkState,
				onClick = onExposedClicked,
				Modifier
					.align(Alignment.BottomEnd)
					.padding(end = 16.dp, bottom = 24.dp)
			)
			ScanIconComponent(
				onClick = {
					navController.navigate(CoreUnlockedNavSubgraph.Camera.destination(null))
				},
				Modifier
					.align(Alignment.BottomCenter)
					.padding(bottom = 24.dp)
			)
		}
	}
}

/**
 * Check if the keyset has any substrate networks (to determine if root QR should be shown)
 */
private fun hasSubstrateNetworks(model: KeySetDetailsModel): Boolean {
	return model.keysAndNetwork.any { keyAndNetwork ->
		val logo = keyAndNetwork.network.networkLogo.lowercase()
		!logo.contains("zcash") && !logo.contains("penumbra") &&
			!logo.contains("noble") && !logo.contains("osmosis") &&
			!logo.contains("celestia") && !logo.contains("cosmos") &&
			!logo.contains("bitcoin") && !logo.contains("nostr") &&
			!logo.contains("atprotocol") && !logo.contains("ethereum")
	}
}

@Composable
private fun SeedKeyItemElement(
	model: KeySetDetailsModel,
	onSeedSelect: Callback,
	onShowRoot: Callback,
) {
	SeedKeyDetails(
		model = model.root,
		onSeedSelect = onSeedSelect,
		onShowRoot = onShowRoot,
		showRootQr = hasSubstrateNetworks(model),
		modifier = Modifier
			.padding(horizontal = 24.dp, vertical = 8.dp)
			.padding(bottom = 16.dp)
	)
}

@Composable
private fun FilterRow(onFilterClicked: Callback) {
	Row(
		modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
		verticalAlignment = Alignment.CenterVertically
	) {
		Text(
			text = stringResource(R.string.key_sets_details_screem_derived_subtitle),
			color = MaterialTheme.colors.textTertiary,
			style = SignerTypeface.BodyM,
			modifier = Modifier.weight(1f),
		)
		Icon(
			painter = painterResource(id = R.drawable.ic_tune_28),
			contentDescription = stringResource(R.string.key_sets_details_screem_filter_icon_description),
			modifier = Modifier
				.clickable(onClick = onFilterClicked)
				.size(28.dp),
			tint = MaterialTheme.colors.pink300,
		)
	}
}


@Composable
fun KeySetDetailsHeader(
	onAddKey: Callback,
	onSettings: Callback,
	onMenu: Callback,
) {
	Row(
		modifier = Modifier
			.fillMaxWidth(1f)
			.defaultMinSize(minHeight = 56.dp),
		verticalAlignment = Alignment.CenterVertically,
	) {
		//start
		SettingsIcon(
			onClick = onSettings,
			noBackground = true,
			modifier = Modifier
				.padding(horizontal = 8.dp)
				.size(40.dp)
				.padding(8.dp)
				.align(Alignment.CenterVertically),
		)
		//center
		Spacer(modifier = Modifier.weight(1f))
		//end
		Image(
			imageVector = Icons.Default.Add,
			contentDescription = stringResource(R.string.key_sets_details_screem_create_derived_button),
			colorFilter = ColorFilter.tint(MaterialTheme.colors.primary),
			modifier = Modifier
				.clickable(onClick = onAddKey)
				.padding(8.dp)
				.size(24.dp)
				.align(Alignment.CenterVertically)
		)
		Image(
			imageVector = Icons.Filled.MoreHoriz,
			contentDescription = stringResource(R.string.description_menu_button),
			colorFilter = ColorFilter.tint(MaterialTheme.colors.primary),
			modifier = Modifier
				.padding(end = 8.dp)
				.clickable(onClick = onMenu)
				.padding(8.dp)
				.size(24.dp)
				.align(Alignment.CenterVertically)
		)
	}
}

/**
 * Not clickable item - disabled automatically
 */
@Composable
fun SeedKeyViewItem(
	seedKeyModel: KeyModel,
	onClick: Callback?,
) {
	Surface(
		modifier = Modifier
			.conditional(onClick != null) {
				clickable(onClick = onClick!!)
			},
		color = Color.Transparent,
	)
	{
		Row(
			modifier = Modifier
				.padding(top = 16.dp, bottom = 16.dp, start = 24.dp),
			verticalAlignment = Alignment.CenterVertically,
		) {
			Column(Modifier.weight(1f)) {
				Text(
					text = seedKeyModel.seedName,
					color = if (onClick != null) MaterialTheme.colors.primary else MaterialTheme.colors.textDisabled,
					style = SignerTypeface.TitleL,
				)
				Text(
					text = seedKeyModel.base58.abbreviateString(BASE58_STYLE_ABBREVIATE),
					color = if (onClick != null) MaterialTheme.colors.textTertiary else MaterialTheme.colors.textDisabled,
					style = SignerTypeface.BodyM,
				)
			}
			if (onClick != null) {
				Image(
					imageVector = Icons.Filled.ChevronRight,
					contentDescription = null,
					colorFilter = ColorFilter.tint(MaterialTheme.colors.textDisabled),
					modifier = Modifier
						.padding(end = 16.dp)
						.size(28.dp)
				)
			}
		}
	}
}

@Composable
private fun KeySetDetailsEmptyList(onAdd: Callback) {
	Column(
		modifier = Modifier
			.fillMaxHeight(1f)
			.padding(horizontal = 16.dp),
		horizontalAlignment = Alignment.CenterHorizontally
	) {
		Spacer(modifier = Modifier.weight(0.5f))

		Column(
			modifier = Modifier
				.background(
					color = MaterialTheme.colors.pink300.copy(alpha = 0.12f),
					shape = RoundedCornerShape(dimensionResource(id = R.dimen.bigCornerRadius)),
				)
				.padding(24.dp)
		)
		{
			Text(
				text = stringResource(R.string.key_set_details_no_keys_title),
				color = MaterialTheme.colors.primary,
				style = SignerTypeface.TitleM,
				textAlign = TextAlign.Center,
			)
			SecondaryButtonWide(
				label = stringResource(R.string.key_sets_details_screem_create_derived_button),
				withBackground = true,
				modifier = Modifier
					.padding(top = 16.dp, bottom = 24.dp, start = 24.dp, end = 24.dp),
				onClicked = onAdd
			)
		}
		Spacer(modifier = Modifier.weight(0.5f))
	}
}

@Composable
private fun MultisigSection(
	onManage: Callback,
) {
	val scope = rememberCoroutineScope()
	var wallets by remember { mutableStateOf<List<FrostWalletSummaryFfi>>(emptyList()) }

	LaunchedEffect(Unit) {
		scope.launch {
			runCatching {
				withContext(Dispatchers.Default) { frostListWallets() }
			}.onSuccess { wallets = it }
		}
	}

	if (wallets.isEmpty()) return

	Row(
		modifier = Modifier
			.clickable(onClick = onManage)
			.padding(horizontal = 24.dp, vertical = 8.dp),
		verticalAlignment = Alignment.CenterVertically,
	) {
		Text(
			text = "Multisig Wallets",
			color = MaterialTheme.colors.textTertiary,
			style = SignerTypeface.BodyM,
			modifier = Modifier.weight(1f),
		)
		Text(
			text = "Manage",
			color = MaterialTheme.colors.pink300,
			style = SignerTypeface.CaptionM,
		)
	}
	for (wallet in wallets) {
		MultisigWalletRow(wallet = wallet, onClick = onManage)
	}
}

@Composable
private fun MultisigWalletRow(
	wallet: FrostWalletSummaryFfi,
	onClick: Callback,
) {
	Row(
		modifier = Modifier
			.fillMaxWidth()
			.clickable(onClick = onClick)
			.padding(horizontal = 24.dp, vertical = 12.dp),
		verticalAlignment = Alignment.CenterVertically,
	) {
		Column(modifier = Modifier.weight(1f)) {
			Row(verticalAlignment = Alignment.CenterVertically) {
				Text(
					text = wallet.label,
					color = MaterialTheme.colors.primary,
					style = SignerTypeface.TitleS,
					modifier = Modifier.weight(1f, fill = false),
				)
				Spacer(modifier = Modifier.size(8.dp))
				Text(
					text = if (wallet.mainnet) "mainnet" else "testnet",
					style = SignerTypeface.CaptionM,
					color = MaterialTheme.colors.textTertiary,
					modifier = Modifier
						.clip(RoundedCornerShape(4.dp))
						.background(MaterialTheme.colors.fill6)
						.padding(horizontal = 6.dp, vertical = 2.dp),
				)
			}
			Text(
				text = "${wallet.minSigners}-of-${wallet.maxSigners} threshold",
				color = MaterialTheme.colors.textSecondary,
				style = SignerTypeface.BodyM,
			)
		}
		Image(
			imageVector = Icons.Filled.ChevronRight,
			contentDescription = null,
			colorFilter = ColorFilter.tint(MaterialTheme.colors.textDisabled),
			modifier = Modifier.size(20.dp),
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
private fun PreviewKeySetDetailsScreen() {
	val state = remember { mutableStateOf(NetworkState.Active) }
	val mockModel = KeySetDetailsModel.createStub()
	val navController = rememberNavController()
	SignerNewTheme {
		Box(modifier = Modifier.size(350.dp, 550.dp)) {
			KeySetDetailsScreenView(
				model = mockModel,
				navController = navController,
				networkState = state,
				fullModelWasEmpty = false,
				onExposedClicked = {},
				onFilterClicked = {},
				onMenu = {},
				onAddNewDerivation = {},
				onSeedSelect = {},
				onShowRoot = {},
				onOpenKey = { _, _ -> },
			)
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
private fun PreviewKeySetDetailsScreenEmpty() {
	val state = remember { mutableStateOf(NetworkState.Active) }
	val mockModel =
		KeySetDetailsModel.createStub().copy(keysAndNetwork = emptyList())
	val navController = rememberNavController()
	SignerNewTheme {
		Box(modifier = Modifier.size(350.dp, 550.dp)) {
			KeySetDetailsScreenView(
				model = mockModel,
				navController = navController,
				networkState = state,
				fullModelWasEmpty = true,
				onExposedClicked = {},
				onFilterClicked = {},
				onMenu = {},
				onAddNewDerivation = {},
				onSeedSelect = {},
				onShowRoot = {},
				onOpenKey = { _, _ -> },
			)
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
private fun PreviewKeySetDetailsScreenFiltered() {
	val state = remember { mutableStateOf(NetworkState.Active) }
	val mockModel =
		KeySetDetailsModel.createStub().copy(keysAndNetwork = emptyList())
	val navController = rememberNavController()
	SignerNewTheme {
		Box(modifier = Modifier.size(350.dp, 550.dp)) {
			KeySetDetailsScreenView(
				model = mockModel,
				navController = navController,
				networkState = state,
				fullModelWasEmpty = false,
				onExposedClicked = {},
				onFilterClicked = {},
				onSeedSelect = {},
				onMenu = {},
				onAddNewDerivation = {},
				onShowRoot = {},
				onOpenKey = { _, _ -> },
			)
		}
	}
}
