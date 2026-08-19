package net.rotko.zigner.screens.createderivation

import android.content.Context
import timber.log.Timber
import android.widget.Toast
import androidx.lifecycle.ViewModel
import net.rotko.zigner.R
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.KeyAndNetworkModel
import net.rotko.zigner.domain.NetworkModel
import net.rotko.zigner.domain.backend.OperationResult
import net.rotko.zigner.domain.backend.mapError
import net.rotko.zigner.domain.storage.SeedRepository
import net.rotko.zigner.domain.storage.mapError
import net.rotko.zigner.domain.toKeyAndNetworkModel
import net.rotko.zigner.domain.usecases.AllNetworksUseCase
import net.rotko.zigner.domain.usecases.CreateDerivationUseCase
import io.parity.signer.uniffi.DerivationCheck
import io.parity.signer.uniffi.keysBySeedName
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.runBlocking


class DerivationCreateViewModel : ViewModel() {

	private val uniffiInteractor = ServiceLocator.uniffiInteractor
	private var seedRepository: SeedRepository =
		ServiceLocator.activityScope!!.seedRepository
	private val pathAnalyzer: DerivationPathAnalyzer = DerivationPathAnalyzer()
	private val allNetworksUseCase = AllNetworksUseCase(uniffiInteractor)
	private val createDerivationUseCase = CreateDerivationUseCase()

	fun getAllNetworks(): List<NetworkModel> = allNetworksUseCase.getAllNetworks()

	private lateinit var seedName: String
	private lateinit var existingKeys: Set<KeyAndNetworkModel>

	private val _path: MutableStateFlow<String> =
		MutableStateFlow(INITIAL_DERIVATION_PATH)
	val path: StateFlow<String> = _path.asStateFlow()

	private val _selectedNetwork: MutableStateFlow<NetworkModel?> =
		MutableStateFlow(null)
	val selectedNetwork: StateFlow<NetworkModel?> =
		_selectedNetwork.asStateFlow()

	fun updatePath(newPath: String) {
		_path.value = newPath
	}

	/**
	 * should be called each time we open this flow again
	 */
	fun refreshCachedDependencies() {
		seedRepository = ServiceLocator.activityScope!!.seedRepository
	}

	fun setInitValues(seed: String) {
		refreshCachedDependencies()
		seedName = seed
		existingKeys =
			keysBySeedName(seed).set.map { it.toKeyAndNetworkModel() }.toSet()
	}

	fun updateSelectedNetwork(newNetwork: NetworkModel) {
		_selectedNetwork.value = newNetwork
		_path.value = getInitialPath(newNetwork)
	}

	suspend fun fastCreateDerivationForNetwork(
		newNetwork: NetworkModel,
		context: Context
	) {
		updateSelectedNetwork(newNetwork)
		proceedCreateKey(context)
	}

	private fun getInitialPath(netWork: NetworkModel): String {
		val base = netWork.pathId
		val keys = existingKeys.filter { it.network.networkSpecsKey == netWork.key }
		val taken = { p: String -> keys.any { it.key.path == p } }
		if (!taken(base)) return base
		// BIP44/ZIP-32 networks (zcash m/32'/133'/account', penumbra
		// m/44'/6532'/0', cosmos m/44'/118'/0'/0/0) derive additional keys by
		// bumping the last numeric segment (account / address index), NOT by
		// appending a substrate `//i` junction which would be an invalid path.
		if (base.startsWith("m/")) {
			return nextBip44Path(base, taken)
		}
		var path = base
		for (i in 0..Int.MAX_VALUE) {
			path = "$base//$i"
			if (!taken(path)) return path
		}
		return path
	}

	/**
	 * Next unused BIP44/ZIP-32 path derived from [base] by incrementing its last
	 * numeric segment, preserving a hardened `'` suffix. e.g.
	 * `m/32'/133'/0'` -> `m/32'/133'/1'`.
	 */
	private fun nextBip44Path(base: String, taken: (String) -> Boolean): String {
		val slash = base.lastIndexOf('/')
		if (slash < 0) return base
		val head = base.substring(0, slash + 1)
		val seg = base.substring(slash + 1)
		val hardened = seg.endsWith("'")
		val num = seg.trimEnd('\'').toIntOrNull() ?: return base
		var i = num + 1
		while (true) {
			val candidate = head + i + (if (hardened) "'" else "")
			if (!taken(candidate)) return candidate
			i++
		}
	}

	fun checkPath(path: String): DerivationPathValidity {
		return when {
			DerivationPathAnalyzer.getPassword(path)
				?.isEmpty() == true -> DerivationPathValidity.EMPTY_PASSWORD

			path.contains(' ') -> DerivationPathValidity.CONTAIN_SPACES
			!pathAnalyzer.isCorrect(path) -> DerivationPathValidity.WRONG_PATH
			else -> {
				val backendCheck = getBackendCheck(path)
				when {
					backendCheck?.collision != null -> DerivationPathValidity.COLLISION_PATH
					backendCheck?.buttonGood == false -> DerivationPathValidity.WRONG_PATH
					else -> DerivationPathValidity.ALL_GOOD
				}
			}
		}
	}

	private fun getBackendCheck(path: String): DerivationCheck? {
		return runBlocking {
			uniffiInteractor.validateDerivationPath(
				path,
				seedName,
				selectedNetwork.value?.key ?: ""
			).mapError()
		}
	}


	suspend fun proceedCreateKey(context: Context) {
		try {
			val phrase =
				seedRepository.getSeedPhraseForceAuth(seedName).mapError() ?: return
			if (phrase.isNotBlank()) {
				val selectedNetwork = selectedNetwork.value!!
				val result = createDerivationUseCase.createDerivation(
					seedName = seedName,
					seedPhrase = phrase,
					path = path.value,
					networkKey = selectedNetwork.key
				)
				System.gc()
				when (result) {
					is OperationResult.Ok -> {
						Toast.makeText(
							context,
							context.getString(R.string.create_derivations_success),
							Toast.LENGTH_SHORT
						).show()
						resetState()
					}

					is OperationResult.Err -> {
						// log full error to logcat for debugging (toast truncates long messages)
						Timber.e(TAG, "create derivation failed: $result.error")
						Toast.makeText(
							context,
							context.getString(
								R.string.create_derivations_failure,
								result.error.localizedMessage ?: result.error.toString()
							),
							Toast.LENGTH_LONG
						).show()
					}
				}
			} else {
				Timber.e(TAG, "Seed phrase received but it's empty")
			}
		} catch (e: java.lang.Exception) {
			Timber.e(TAG, e.toString())
		}
	}

	fun resetState() {
		_path.value = INITIAL_DERIVATION_PATH
	}

	enum class DerivationPathValidity {
		ALL_GOOD, WRONG_PATH, COLLISION_PATH, EMPTY_PASSWORD, CONTAIN_SPACES
	}
}

internal const val INITIAL_DERIVATION_PATH = "//"
private const val TAG = "DerivationCreateViewModel"

