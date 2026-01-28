package net.rotko.zigner.screens.scan.backuprestore

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import net.rotko.zigner.R
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.backend.AuthOperationResult
import net.rotko.zigner.domain.backend.UniffiResult
import net.rotko.zigner.domain.storage.SeedRepository
import net.rotko.zigner.domain.usecases.CreateKeySetUseCase
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.json.JSONObject

data class BackupData(
	val seedName: String,
	val accounts: List<AccountBackup>
)

data class AccountBackup(
	val path: String,
	val genesisHash: String?,
	val networkName: String?,
	val encryption: String?
)

class BackupRestoreViewModel : ViewModel() {

	private val uniffiInteractor = ServiceLocator.uniffiInteractor
	private val seedRepository: SeedRepository by lazy { ServiceLocator.activityScope!!.seedRepository }
	private val createKeySetUseCase = CreateKeySetUseCase()

	private val _isSuccessTerminal = MutableStateFlow<String?>(null)
	val isSuccessTerminal = _isSuccessTerminal.asStateFlow()

	private val _isErrorTerminal = MutableStateFlow<String?>(null)
	val isErrorTerminal = _isErrorTerminal.asStateFlow()

	private val _isLoading = MutableStateFlow(false)
	val isLoading = _isLoading.asStateFlow()

	private val _backupData = MutableStateFlow<BackupData?>(null)
	val backupData = _backupData.asStateFlow()

	private val _seedExists = MutableStateFlow(false)
	val seedExists = _seedExists.asStateFlow()

	private val _seedName = MutableStateFlow("")
	val seedName = _seedName.asStateFlow()

	fun cleanState() {
		_isSuccessTerminal.value = null
		_isErrorTerminal.value = null
		_isLoading.value = false
		_backupData.value = null
		_seedExists.value = false
		_seedName.value = ""
	}

	fun initWithUrFrames(urFrames: List<String>, context: Context) {
		viewModelScope.launch {
			_isLoading.value = true
			try {
				when (val result = uniffiInteractor.decodeBackupUr(urFrames)) {
					is UniffiResult.Success -> {
						val json = result.result
						parseBackupJson(json, context)
					}
					is UniffiResult.Error -> {
						_isErrorTerminal.value = result.error.message
							?: context.getString(R.string.backup_restore_error_decode)
					}
				}
			} catch (e: Exception) {
				_isErrorTerminal.value = e.message
					?: context.getString(R.string.backup_restore_error_decode)
			} finally {
				_isLoading.value = false
			}
		}
	}

	private fun parseBackupJson(json: String, context: Context) {
		try {
			val jsonObj = JSONObject(json)
			val version = jsonObj.optInt("v", 1)
			val seedName = jsonObj.getString("name")

			// v2 format: no seed phrase, must match existing seed
			if (version >= 2) {
				// Check if seed exists - required for v2
				if (!seedRepository.containSeedName(seedName)) {
					_isErrorTerminal.value = context.getString(R.string.backup_restore_error_seed_not_found, seedName)
					return
				}
				_seedExists.value = true
			} else {
				// v1 fallback (shouldn't happen with new exports)
				_isErrorTerminal.value = "Unsupported backup format version"
				return
			}

			// Parse accounts with new format: genesis_hash, network (name), encryption
			val accounts = mutableListOf<AccountBackup>()
			val accountsArray = jsonObj.optJSONArray("accounts")
			if (accountsArray != null) {
				for (i in 0 until accountsArray.length()) {
					val accountObj = accountsArray.getJSONObject(i)
					accounts.add(
						AccountBackup(
							path = accountObj.getString("path"),
							genesisHash = accountObj.optString("genesis_hash", null),
							networkName = accountObj.optString("network", null),
							encryption = accountObj.optString("encryption", null)
						)
					)
				}
			}

			_backupData.value = BackupData(seedName, accounts)
			_seedName.value = seedName
		} catch (e: Exception) {
			_isErrorTerminal.value = context.getString(R.string.backup_restore_error_invalid_format)
		}
	}

	suspend fun restoreBackup(context: Context) {
		val backup = _backupData.value ?: return

		_isLoading.value = true
		try {
			// For v2 (metadata-only), derive accounts for existing seed
			val result = createKeySetUseCase.deriveAccountsForExistingSeed(
				seedName = _seedName.value,
				accounts = backup.accounts.mapNotNull { account ->
					// Use genesis_hash to look up network, or network name as fallback
					val genesisHash = account.genesisHash
					if (genesisHash != null) {
						CreateKeySetUseCase.AccountDerivation(
							path = account.path,
							genesisHash = genesisHash,
							encryption = account.encryption
						)
					} else {
						null
					}
				}
			)

			when (result) {
				AuthOperationResult.Success -> {
					_isSuccessTerminal.value = _seedName.value
				}
				is AuthOperationResult.Error -> {
					_isErrorTerminal.value = result.exception.message
						?: context.getString(R.string.backup_restore_error_save)
				}
				is AuthOperationResult.AuthFailed -> {
					_isErrorTerminal.value = context.getString(R.string.backup_restore_error_auth)
				}
			}
		} catch (e: Exception) {
			_isErrorTerminal.value = e.message ?: context.getString(R.string.backup_restore_error_save)
		} finally {
			_isLoading.value = false
		}
	}
}
