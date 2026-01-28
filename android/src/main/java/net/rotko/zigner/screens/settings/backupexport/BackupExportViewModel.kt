package net.rotko.zigner.screens.settings.backupexport

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.backend.UniffiResult
import io.parity.signer.uniffi.QrData
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class BackupExportViewModel : ViewModel() {

	private val uniffiInteractor = ServiceLocator.uniffiInteractor

	private val _qrFrames = MutableStateFlow<List<QrData>?>(null)
	val qrFrames = _qrFrames.asStateFlow()

	private val _isLoading = MutableStateFlow(false)
	val isLoading = _isLoading.asStateFlow()

	private val _error = MutableStateFlow<String?>(null)
	val error = _error.asStateFlow()

	fun loadBackupQr(seedName: String, seedPhrase: String) {
		viewModelScope.launch {
			_isLoading.value = true
			_error.value = null

			when (val result = uniffiInteractor.exportBackupQr(seedName, seedPhrase, 300u)) {
				is UniffiResult.Success -> {
					_qrFrames.value = result.result
				}
				is UniffiResult.Error -> {
					_error.value = result.error.message ?: "Failed to generate backup QR"
				}
			}

			_isLoading.value = false
		}
	}

	fun clearState() {
		_qrFrames.value = null
		_error.value = null
		_isLoading.value = false
	}
}
