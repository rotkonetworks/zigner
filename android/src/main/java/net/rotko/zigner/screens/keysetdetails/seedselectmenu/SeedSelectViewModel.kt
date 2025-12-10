package net.rotko.zigner.screens.keysetdetails.seedselectmenu

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.KeySetsListModel
import net.rotko.zigner.domain.backend.UniffiResult
import net.rotko.zigner.domain.mapState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.mapLatest
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.withContext


class SeedSelectViewModel : ViewModel() {
	private val seedStorage = ServiceLocator.seedStorage
	private val uniffiInteractor = ServiceLocator.uniffiInteractor

	@OptIn(ExperimentalCoroutinesApi::class)
	val keySetModel: StateFlow<UniffiResult<KeySetsListModel>> =
		seedStorage.lastKnownSeedNames.mapLatest {
			withContext(Dispatchers.IO) {
				uniffiInteractor.getKeySets(it.toList())
			}
		}.stateIn(
			viewModelScope,
			SharingStarted.Eagerly,
			UniffiResult.Success(KeySetsListModel(emptyList()))
		)

}



