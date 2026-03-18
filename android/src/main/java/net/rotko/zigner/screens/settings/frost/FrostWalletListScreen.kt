package net.rotko.zigner.screens.settings.frost

import android.content.res.Configuration
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import io.parity.signer.uniffi.FrostWalletSummaryFfi
import io.parity.signer.uniffi.frostDeleteWallet
import io.parity.signer.uniffi.frostListWallets
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.rotko.zigner.components.base.ScreenHeaderClose
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*

@Composable
fun FrostWalletListScreen(
	onBack: Callback,
) {
	var wallets by remember { mutableStateOf<List<FrostWalletSummaryFfi>>(emptyList()) }
	var error by remember { mutableStateOf<String?>(null) }
	var confirmDeleteId by remember { mutableStateOf<String?>(null) }
	val scope = rememberCoroutineScope()

	fun loadWallets() {
		scope.launch {
			try {
				val result = withContext(Dispatchers.Default) {
					frostListWallets()
				}
				wallets = result
				error = null
			} catch (e: Exception) {
				error = e.message ?: "Failed to load wallets"
			}
		}
	}

	LaunchedEffect(Unit) {
		loadWallets()
	}

	Column(
		modifier = Modifier
			.fillMaxSize()
			.background(MaterialTheme.colors.background)
			.statusBarsPadding()
	) {
		ScreenHeaderClose(
			title = "FROST Multisig Wallets",
			onClose = onBack,
		)

		if (error != null) {
			Text(
				text = error!!,
				style = SignerTypeface.BodyL,
				color = MaterialTheme.colors.red500,
				modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp),
			)
		}

		if (wallets.isEmpty() && error == null) {
			Column(
				modifier = Modifier
					.fillMaxSize()
					.padding(horizontal = 24.dp),
				horizontalAlignment = Alignment.CenterHorizontally,
				verticalArrangement = Arrangement.Center,
			) {
				Text(
					text = "No multisig wallets",
					style = SignerTypeface.TitleS,
					color = MaterialTheme.colors.textTertiary,
				)
				Spacer(modifier = Modifier.height(8.dp))
				Text(
					text = "Complete a FROST DKG ceremony to create one.",
					style = SignerTypeface.CaptionM,
					color = MaterialTheme.colors.textTertiary,
				)
			}
		} else {
			Column(
				modifier = Modifier
					.weight(1f)
					.verticalScroll(rememberScrollState())
			) {
				wallets.forEach { wallet ->
					FrostWalletRow(
						wallet = wallet,
						isConfirmingDelete = confirmDeleteId == wallet.walletId,
						onDeleteTap = {
							confirmDeleteId = wallet.walletId
						},
						onDeleteConfirm = {
							scope.launch {
								try {
									withContext(Dispatchers.Default) {
										frostDeleteWallet(wallet.walletId)
									}
									confirmDeleteId = null
									loadWallets()
								} catch (e: Exception) {
									error = e.message ?: "Failed to delete wallet"
								}
							}
						},
						onDeleteCancel = {
							confirmDeleteId = null
						},
					)
					SignerDivider()
				}
			}
		}
	}
}

@Composable
private fun FrostWalletRow(
	wallet: FrostWalletSummaryFfi,
	isConfirmingDelete: Boolean,
	onDeleteTap: Callback,
	onDeleteConfirm: Callback,
	onDeleteCancel: Callback,
) {
	Column(
		modifier = Modifier
			.fillMaxWidth()
			.padding(horizontal = 24.dp, vertical = 16.dp)
	) {
		// Label and network badge
		Row(
			verticalAlignment = Alignment.CenterVertically,
		) {
			Text(
				text = wallet.label,
				style = SignerTypeface.TitleS,
				color = MaterialTheme.colors.primary,
				modifier = Modifier.weight(1f),
			)
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

		Spacer(modifier = Modifier.height(4.dp))

		// Threshold
		Text(
			text = "${wallet.minSigners}-of-${wallet.maxSigners} threshold",
			style = SignerTypeface.BodyL,
			color = MaterialTheme.colors.textSecondary,
		)

		Spacer(modifier = Modifier.height(4.dp))

		// Wallet ID (truncated)
		Text(
			text = wallet.walletId.take(16) + "...",
			style = SignerTypeface.CaptionM,
			color = MaterialTheme.colors.textTertiary,
		)

		Spacer(modifier = Modifier.height(12.dp))

		if (isConfirmingDelete) {
			Text(
				text = "Delete this wallet? This cannot be undone.",
				style = SignerTypeface.CaptionM,
				color = MaterialTheme.colors.red500,
				modifier = Modifier.padding(bottom = 8.dp),
			)
			Row(
				modifier = Modifier.fillMaxWidth(),
				horizontalArrangement = Arrangement.spacedBy(12.dp),
			) {
				SecondaryButtonWide(
					label = "Cancel",
					modifier = Modifier.weight(1f),
					onClicked = onDeleteCancel,
				)
				SecondaryButtonWide(
					label = "Delete",
					modifier = Modifier.weight(1f),
					onClicked = onDeleteConfirm,
				)
			}
		} else {
			SecondaryButtonWide(
				label = "Delete",
				modifier = Modifier.fillMaxWidth(),
				onClicked = onDeleteTap,
			)
		}
	}
}

@Preview(
	name = "light", group = "themes",
	uiMode = Configuration.UI_MODE_NIGHT_NO,
	showBackground = true, backgroundColor = 0xFFFFFFFF,
)
@Preview(
	name = "dark", group = "themes",
	uiMode = Configuration.UI_MODE_NIGHT_YES,
	showBackground = true, backgroundColor = 0xFF000000,
)
@Composable
private fun PreviewFrostWalletListEmpty() {
	SignerNewTheme {
		FrostWalletListContent(
			wallets = emptyList(),
			error = null,
			confirmDeleteId = null,
			onDeleteTap = {},
			onDeleteConfirm = {},
			onDeleteCancel = {},
			onBack = {},
		)
	}
}

@Preview(
	name = "light_with_wallets", group = "themes",
	uiMode = Configuration.UI_MODE_NIGHT_NO,
	showBackground = true, backgroundColor = 0xFFFFFFFF,
)
@Composable
private fun PreviewFrostWalletListPopulated() {
	SignerNewTheme {
		FrostWalletListContent(
			wallets = listOf(
				FrostWalletSummaryFfi(
					walletId = "abcdef0123456789abcdef0123456789",
					label = "Treasury",
					minSigners = 2.toUShort(),
					maxSigners = 3.toUShort(),
					mainnet = true,
					createdAt = 1700000000uL,
				),
				FrostWalletSummaryFfi(
					walletId = "1234567890abcdef1234567890abcdef",
					label = "Test Wallet",
					minSigners = 3.toUShort(),
					maxSigners = 5.toUShort(),
					mainnet = false,
					createdAt = 1700100000uL,
				),
			),
			error = null,
			confirmDeleteId = null,
			onDeleteTap = {},
			onDeleteConfirm = {},
			onDeleteCancel = {},
			onBack = {},
		)
	}
}

/**
 * Stateless content composable for previews.
 */
@Composable
private fun FrostWalletListContent(
	wallets: List<FrostWalletSummaryFfi>,
	error: String?,
	confirmDeleteId: String?,
	onDeleteTap: (String) -> Unit,
	onDeleteConfirm: Callback,
	onDeleteCancel: Callback,
	onBack: Callback,
) {
	Column(
		modifier = Modifier
			.fillMaxSize()
			.background(MaterialTheme.colors.background)
	) {
		ScreenHeaderClose(
			title = "FROST Multisig Wallets",
			onClose = onBack,
		)

		if (error != null) {
			Text(
				text = error,
				style = SignerTypeface.BodyL,
				color = MaterialTheme.colors.red500,
				modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp),
			)
		}

		if (wallets.isEmpty() && error == null) {
			Column(
				modifier = Modifier
					.fillMaxSize()
					.padding(horizontal = 24.dp),
				horizontalAlignment = Alignment.CenterHorizontally,
				verticalArrangement = Arrangement.Center,
			) {
				Text(
					text = "No multisig wallets",
					style = SignerTypeface.TitleS,
					color = MaterialTheme.colors.textTertiary,
				)
				Spacer(modifier = Modifier.height(8.dp))
				Text(
					text = "Complete a FROST DKG ceremony to create one.",
					style = SignerTypeface.CaptionM,
					color = MaterialTheme.colors.textTertiary,
				)
			}
		} else {
			Column(
				modifier = Modifier
					.weight(1f)
					.verticalScroll(rememberScrollState())
			) {
				wallets.forEach { wallet ->
					FrostWalletRow(
						wallet = wallet,
						isConfirmingDelete = confirmDeleteId == wallet.walletId,
						onDeleteTap = { onDeleteTap(wallet.walletId) },
						onDeleteConfirm = onDeleteConfirm,
						onDeleteCancel = onDeleteCancel,
					)
					SignerDivider()
				}
			}
		}
	}
}
