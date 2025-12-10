package net.rotko.zigner.screens.keydetails

import androidx.lifecycle.ViewModel
import net.rotko.zigner.bottomsheets.password.EnterPasswordModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.KeyDetailsModel
import net.rotko.zigner.domain.backend.OperationResult
import net.rotko.zigner.domain.backend.UniffiResult
import net.rotko.zigner.domain.storage.RepoResult
import net.rotko.zigner.screens.keydetails.exportprivatekey.PrivateKeyExportModel
import io.parity.signer.uniffi.MKeyDetails
import io.parity.signer.uniffi.encodeToQr
import io.parity.signer.uniffi.exportZcashFvk
import io.parity.signer.uniffi.exportPenumbraFvk


class KeyDetailsScreenViewModel : ViewModel() {
	private val uniFfi = ServiceLocator.uniffiInteractor
	private val repo = ServiceLocator.activityScope!!.seedRepository

	//keeping this state because we don't want to ask for password twice
	private var privateExportStateModel: PrivateKeyExportModel? = null

	suspend fun fetchModel(
		keyAddr: String,
		networkSpecs: String
	): UniffiResult<MKeyDetails> {
		return uniFfi.getKeyPublicKey(keyAddr, networkSpecs)
	}

	suspend fun getPrivateExportKey(
		model: KeyDetailsModel,
		password: String?
	): OperationResult<PrivateKeyExportModel, Any> {

		privateExportStateModel?.let { saved ->
			if (saved.keyCard == model.address) {
				//password check result saved or already saved before config change
				return OperationResult.Ok(saved)
			}
		}

		val seedResult =
			repo.getSeedPhraseForceAuth(model.address.cardBase.seedName)
		return when (seedResult) {
			is RepoResult.Failure -> OperationResult.Err(seedResult)
			is RepoResult.Success -> {
				val secretKeyDetailsQR = uniFfi.generateSecretKeyQr(
					publicKey = model.pubkey,
					expectedSeedName = model.address.cardBase.seedName,
					networkSpecsKey = model.networkInfo.networkSpecsKey,
					seedPhrase = seedResult.result,
					keyPassword = password,
				)
				System.gc()
				when (secretKeyDetailsQR) {
					is UniffiResult.Error -> OperationResult.Err(secretKeyDetailsQR.error)
					is UniffiResult.Success -> {
						privateExportStateModel = secretKeyDetailsQR.result
						OperationResult.Ok(secretKeyDetailsQR.result)
					}
				}
			}
		}
	}

	fun clearExportResultState() {
		privateExportStateModel = null
	}

	fun createPasswordModel(keyModel: KeyDetailsModel): EnterPasswordModel {
		return EnterPasswordModel(
			keyCard = keyModel.address.cardBase,
			showError = false,
			attempt = 0,
		)
	}

	suspend fun tryPassword(
		keyModel: KeyDetailsModel,
		passwordModel: EnterPasswordModel,
		password: String
	): ExportTryPasswordReply {
		val seedResult = if (passwordModel.attempt == 0) {
			repo.getSeedPhraseForceAuth(keyModel.address.cardBase.seedName)
		} else {
			repo.getSeedPhrases(listOf(keyModel.address.cardBase.seedName))
		}

		return when (seedResult) {
			is RepoResult.Failure -> {
				ExportTryPasswordReply.ErrorAuthWrong
			}

			is RepoResult.Success -> {
				val secretKeyDetailsQR = uniFfi.generateSecretKeyQr(
					publicKey = keyModel.pubkey,
					expectedSeedName = keyModel.address.cardBase.seedName,
					networkSpecsKey = keyModel.networkInfo.networkSpecsKey,
					seedPhrase = seedResult.result,
					keyPassword = password,
				)
				System.gc()

				when (secretKeyDetailsQR) {
					is UniffiResult.Error -> {
						if (passwordModel.attempt > 3) {
							ExportTryPasswordReply.ErrorAttemptsExceeded
						} else {
							ExportTryPasswordReply.UpdatePassword(
								passwordModel.copy(
									showError = true,
									attempt = passwordModel.attempt + 1
								)
							)
						}
					}

					is UniffiResult.Success -> {
						privateExportStateModel = secretKeyDetailsQR.result
						ExportTryPasswordReply.OK(password)
					}
				}
			}
		}
	}

	suspend fun removeDerivedKey(
		addressKey: String,
		networkSpecsKey: String,
	): UniffiResult<Unit> {
		return uniFfi.removedDerivedKey(addressKey, networkSpecsKey)
	}

	suspend fun exportFvk(
		seedName: String,
		networkLogo: String,
		accountIndex: UInt = 0u,
		label: String = "",
		mainnet: Boolean = true
	): FvkExportResult? {
		val seedResult = repo.getSeedPhraseForceAuth(seedName)
		return when (seedResult) {
			is RepoResult.Failure -> null
			is RepoResult.Success -> {
				try {
					when {
						networkLogo.lowercase().contains("zcash") -> {
							val export = exportZcashFvk(seedResult.result, accountIndex, label, mainnet)
							val qrPng = encodeToQr(export.qrData, false)
							FvkExportResult(
								displayKey = export.fvkHex,
								qrPng = qrPng.toList(),
								label = export.label,
								networkType = "zcash"
							)
						}
						networkLogo.lowercase().contains("penumbra") -> {
							val export = exportPenumbraFvk(seedResult.result, accountIndex, label)
							val qrPng = encodeToQr(export.qrData, false)
							FvkExportResult(
								displayKey = export.fvkBech32m,
								qrPng = qrPng.toList(),
								label = export.label,
								networkType = "penumbra"
							)
						}
						else -> null
					}
				} catch (e: Exception) {
					null
				}
			}
		}
	}
}

data class FvkExportResult(
	val displayKey: String,
	val qrPng: List<UByte>,
	val label: String,
	val networkType: String
)

sealed class ExportTryPasswordReply {
	data class OK(val password: String) : ExportTryPasswordReply()
	data class UpdatePassword(val model: EnterPasswordModel) :
		ExportTryPasswordReply()

	data object ErrorAttemptsExceeded : ExportTryPasswordReply()
	data object ErrorAuthWrong : ExportTryPasswordReply()
}

