package net.rotko.zigner.domain.usecases

import net.rotko.zigner.domain.FeatureFlags
import net.rotko.zigner.domain.FeatureOption
import net.rotko.zigner.domain.backend.UniffiResult
import io.parity.signer.uniffi.ErrorDisplayed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext


class DBVersionValidationUseCase {

	suspend fun validate(): UniffiResult<Unit> = withContext(Dispatchers.IO) {
		if (FeatureFlags.isEnabled(FeatureOption.FAIL_DB_VERSION_CHECK)) {
			return@withContext UniffiResult.Error(ErrorDisplayed.DbSchemaMismatch())
		}
		try {
			io.parity.signer.uniffi.checkDbVersion()
			UniffiResult.Success(Unit)
		} catch (e: ErrorDisplayed) {
			UniffiResult.Error(e)
		}
	}
}
