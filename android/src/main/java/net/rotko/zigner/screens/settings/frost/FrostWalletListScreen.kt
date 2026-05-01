package net.rotko.zigner.screens.settings.frost

import android.content.Context
import android.content.res.Configuration
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.Icon
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.FileDownload
import androidx.compose.material.icons.outlined.QrCode2
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import io.parity.signer.uniffi.FrostWalletSummaryFfi
import io.parity.signer.uniffi.frostDeleteWallet
import io.parity.signer.uniffi.frostExportBackupEnvelope
import io.parity.signer.uniffi.frostImportBackupEnvelope
import io.parity.signer.uniffi.frostListWallets
import io.parity.signer.uniffi.frostRenameWallet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.rotko.zigner.components.base.PrimaryButtonWide
import net.rotko.zigner.components.base.ScreenHeaderClose
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.components.base.SignerDivider
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*
import timber.log.Timber

@Composable
fun FrostWalletListScreen(
	onBack: Callback,
	onSendWalletToZafu: (walletId: String) -> Unit = {},
) {
	val ctx = LocalContext.current
	var wallets by remember { mutableStateOf<List<FrostWalletSummaryFfi>>(emptyList()) }
	var error by remember { mutableStateOf<String?>(null) }
	var toast by remember { mutableStateOf<String?>(null) }
	var confirmDeleteId by remember { mutableStateOf<String?>(null) }
	var renameTarget by remember { mutableStateOf<FrostWalletSummaryFfi?>(null) }
	val scope = rememberCoroutineScope()

	// Backup-export flow: passphrase entry → SAF write
	var exportTarget by remember { mutableStateOf<FrostWalletSummaryFfi?>(null) }
	var pendingEnvelope by remember { mutableStateOf<String?>(null) }
	var pendingFilename by remember { mutableStateOf("frost-backup.json") }
	val saveLauncher = rememberLauncherForActivityResult(
		ActivityResultContracts.CreateDocument("application/json")
	) { uri: Uri? ->
		val envelope = pendingEnvelope
		pendingEnvelope = null
		if (uri != null && envelope != null) {
			scope.launch {
				try {
					withContext(Dispatchers.IO) { writeFile(ctx, uri, envelope) }
					toast = "backup saved"
				} catch (e: Exception) {
					Timber.e(e, "[frost-backup] save failed")
					error = e.message ?: "save failed"
				}
			}
		}
	}

	// Backup-import flow: SAF read → passphrase entry → frost_import_backup_envelope
	var importEnvelopeJson by remember { mutableStateOf<String?>(null) }
	val openLauncher = rememberLauncherForActivityResult(
		ActivityResultContracts.OpenDocument()
	) { uri: Uri? ->
		if (uri != null) {
			scope.launch {
				try {
					val text = withContext(Dispatchers.IO) { readFile(ctx, uri) }
					importEnvelopeJson = text
				} catch (e: Exception) {
					Timber.e(e, "[frost-backup] read failed")
					error = e.message ?: "read failed"
				}
			}
		}
	}

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
		if (toast != null) {
			Text(
				text = toast!!,
				style = SignerTypeface.CaptionM,
				color = MaterialTheme.colors.accentGreen,
				modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
			)
			LaunchedEffect(toast) {
				kotlinx.coroutines.delay(3000)
				toast = null
			}
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
					text = "Complete a FROST DKG ceremony to create one,\nor restore from an encrypted backup.",
					style = SignerTypeface.CaptionM,
					color = MaterialTheme.colors.textTertiary,
				)
				Spacer(modifier = Modifier.height(24.dp))
				SecondaryButtonWide(
					label = "Restore from file",
					modifier = Modifier.padding(horizontal = 24.dp),
					onClicked = { openLauncher.launch(arrayOf("application/json")) },
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
						onExportBackup = { exportTarget = wallet },
						onSendToZafu = { onSendWalletToZafu(wallet.walletId) },
						onRenameTap = { renameTarget = wallet },
					)
					SignerDivider()
				}
				Spacer(modifier = Modifier.height(16.dp))
				SecondaryButtonWide(
					label = "Restore from file",
					modifier = Modifier.padding(horizontal = 24.dp, vertical = 4.dp),
					onClicked = { openLauncher.launch(arrayOf("application/json")) },
				)
				Spacer(modifier = Modifier.height(24.dp))
			}
		}
	}

	// ── Export passphrase dialog ──
	exportTarget?.let { wallet ->
		FrostBackupDialog(
			title = "Export \"${wallet.label}\"",
			subtitle = "Encrypts the FROST share with a passphrase you choose. Save the file somewhere safe — paper, USB drive, password manager.",
			confirmLabel = "Export",
			requireConfirmField = true,
			onConfirm = { passphrase ->
				exportTarget = null
				scope.launch {
					try {
						val envelope = withContext(Dispatchers.Default) {
							frostExportBackupEnvelope(wallet.walletId, passphrase)
						}
						pendingEnvelope = envelope
						pendingFilename = "frost-backup-${sanitizeLabel(wallet.label)}-${ymdToday()}.json"
						saveLauncher.launch(pendingFilename)
					} catch (e: Exception) {
						Timber.e(e, "[frost-backup] export failed")
						error = e.message ?: "export failed"
					}
				}
			},
			onCancel = { exportTarget = null },
		)
	}

	// ── Rename dialog ──
	renameTarget?.let { wallet ->
		FrostRenameDialog(
			currentLabel = wallet.label,
			onConfirm = { newLabel ->
				renameTarget = null
				scope.launch {
					try {
						withContext(Dispatchers.Default) {
							frostRenameWallet(wallet.walletId, newLabel)
						}
						toast = "renamed to \"$newLabel\""
						loadWallets()
					} catch (e: Exception) {
						Timber.e(e, "[frost-rename] failed")
						error = e.message ?: "rename failed"
					}
				}
			},
			onCancel = { renameTarget = null },
		)
	}

	// ── Import passphrase dialog ──
	importEnvelopeJson?.let { json ->
		FrostBackupDialog(
			title = "Restore backup",
			subtitle = "Enter the passphrase used when this file was exported.",
			confirmLabel = "Restore",
			requireConfirmField = false,
			onConfirm = { passphrase ->
				importEnvelopeJson = null
				scope.launch {
					try {
						val newId = withContext(Dispatchers.Default) {
							frostImportBackupEnvelope(json, passphrase)
						}
						toast = "wallet restored"
						loadWallets()
						Timber.d("[frost-backup] imported wallet=$newId")
					} catch (e: Exception) {
						Timber.e(e, "[frost-backup] import failed")
						error = e.message ?: "import failed"
					}
				}
			},
			onCancel = { importEnvelopeJson = null },
		)
	}
}

@Composable
private fun FrostWalletRow(
	wallet: FrostWalletSummaryFfi,
	isConfirmingDelete: Boolean,
	onDeleteTap: Callback,
	onDeleteConfirm: Callback,
	onDeleteCancel: Callback,
	onExportBackup: Callback = {},
	onSendToZafu: Callback = {},
	onRenameTap: Callback = {},
) {
	Column(
		modifier = Modifier
			.fillMaxWidth()
			.padding(horizontal = 24.dp, vertical = 16.dp)
	) {
		// Label, inline rename pencil, network badge.
		Row(
			verticalAlignment = Alignment.CenterVertically,
		) {
			Text(
				text = wallet.label,
				style = SignerTypeface.TitleS,
				color = MaterialTheme.colors.primary,
			)
			Spacer(modifier = Modifier.width(6.dp))
			Box(
				modifier = Modifier
					.size(28.dp)
					.clip(RoundedCornerShape(6.dp))
					.clickable(onClick = onRenameTap),
				contentAlignment = Alignment.Center,
			) {
				Icon(
					imageVector = Icons.Outlined.Edit,
					contentDescription = "Rename",
					tint = MaterialTheme.colors.textTertiary,
					modifier = Modifier.size(14.dp),
				)
			}
			Spacer(modifier = Modifier.weight(1f))
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
			// Compact icon-button row. Long-press any icon for a Toast tooltip.
			// Rename lives inline next to the wallet label, not in this row.
			Row(
				modifier = Modifier.fillMaxWidth(),
				horizontalArrangement = Arrangement.spacedBy(8.dp),
			) {
				IconActionButton(
					icon = Icons.Outlined.QrCode2,
					label = "Send to zafu",
					onClick = onSendToZafu,
					modifier = Modifier.weight(1f),
				)
				IconActionButton(
					icon = Icons.Outlined.FileDownload,
					label = "Backup",
					onClick = onExportBackup,
					modifier = Modifier.weight(1f),
				)
				IconActionButton(
					icon = Icons.Outlined.Delete,
					label = "Delete",
					onClick = onDeleteTap,
					tint = MaterialTheme.colors.red400,
					modifier = Modifier.weight(1f),
				)
			}
		}
	}
}

// ── helpers ──

/** sanitize wallet label for filename use ([A-Za-z0-9_-] only). */
internal fun sanitizeLabel(label: String): String {
	val cleaned = label.replace(Regex("[^A-Za-z0-9_-]+"), "-").trim('-')
	return if (cleaned.isEmpty()) "multisig" else cleaned
}

/** YYYYMMDD in local time. */
internal fun ymdToday(): String {
	val cal = java.util.Calendar.getInstance()
	val y = cal.get(java.util.Calendar.YEAR)
	val m = cal.get(java.util.Calendar.MONTH) + 1
	val d = cal.get(java.util.Calendar.DAY_OF_MONTH)
	return "%04d%02d%02d".format(y, m, d)
}

private fun writeFile(ctx: Context, uri: Uri, text: String) {
	ctx.contentResolver.openOutputStream(uri)?.use { os ->
		os.write(text.toByteArray(Charsets.UTF_8))
	} ?: throw IllegalStateException("could not open output stream for $uri")
}

private fun readFile(ctx: Context, uri: Uri): String {
	return ctx.contentResolver.openInputStream(uri)?.use { input ->
		input.readBytes().toString(Charsets.UTF_8)
	} ?: throw IllegalStateException("could not open input stream for $uri")
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
