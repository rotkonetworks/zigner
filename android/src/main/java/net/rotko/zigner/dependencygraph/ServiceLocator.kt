package net.rotko.zigner.dependencygraph

import android.content.Context
import androidx.fragment.app.FragmentActivity
import net.rotko.zigner.domain.backend.UniffiInteractor
import net.rotko.zigner.components.networkicon.UnknownNetworkColorsGenerator
import net.rotko.zigner.domain.Authentication
import net.rotko.zigner.domain.NetworkExposedStateKeeper
import net.rotko.zigner.domain.storage.BananaSplitRepository
import net.rotko.zigner.domain.storage.ClearCryptedStorage
import net.rotko.zigner.domain.storage.DatabaseAssetsInteractor
import net.rotko.zigner.domain.storage.PreferencesRepository
import net.rotko.zigner.domain.storage.SeedRepository
import net.rotko.zigner.domain.storage.SeedStorage

object ServiceLocator {

	lateinit var appContext: Context

	fun initAppDependencies(appContext: Context) {
		this.appContext = appContext
	}

	fun initActivityDependencies(activity: FragmentActivity) {
		_activityScope = ActivityScope(activity)
	}

	fun deinitActivityDependencies() {
		_activityScope = null
	}

	@Volatile
	private var _activityScope: ActivityScope? = null
	val activityScope: ActivityScope? get() = _activityScope

	val uniffiInteractor by lazy { UniffiInteractor(appContext) }

	val seedStorage: SeedStorage = SeedStorage()
	val clearCryptedStorage: ClearCryptedStorage = ClearCryptedStorage()
	val preferencesRepository: PreferencesRepository by lazy {
		PreferencesRepository(
			appContext
		)
	}
	val databaseAssetsInteractor by lazy {
		DatabaseAssetsInteractor(
			appContext,
			seedStorage,
			clearCryptedStorage,
		)
	}
	val networkExposedStateKeeper by lazy {
		NetworkExposedStateKeeper(
			appContext,
			uniffiInteractor,
			preferencesRepository
		)
	}
	val authentication = Authentication()
	val unknownNetworkColorsGenerator: UnknownNetworkColorsGenerator =
		UnknownNetworkColorsGenerator()

	class ActivityScope(val activity: FragmentActivity) {
		val seedRepository: SeedRepository = SeedRepository(
			seedStorage = seedStorage,
			clearCryptedStorage = clearCryptedStorage,
			authentication = authentication,
			activity = activity,
			uniffiInteractor = uniffiInteractor,
		)

		val bsRepository: BananaSplitRepository = BananaSplitRepository(
			seedStorage = seedStorage,
			clearCryptedStorage = clearCryptedStorage,
			authentication = authentication,
			activity = activity,
			uniffiInteractor = uniffiInteractor,
		)
	}
}

