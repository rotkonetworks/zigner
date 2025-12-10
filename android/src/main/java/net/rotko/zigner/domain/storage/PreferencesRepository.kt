package net.rotko.zigner.domain.storage

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.single

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "app_preferences")

class PreferencesRepository(private val context: Context) {

	private val networksFilterKey = stringSetPreferencesKey("network_filter")
	private val lastSelectedKeySet = stringPreferencesKey("last_selected_seed_name")
	private val onlineModeEnabledKey = booleanPreferencesKey("online_mode_enabled")

	val networksFilter = context.dataStore.data
		.map { preferences ->
			// No type safety.
			preferences[networksFilterKey] ?: emptySet()
		}

	suspend fun setNetworksFilter(newFilters: Set<String>) {
		context.dataStore.edit { settings ->
			settings[networksFilterKey] = newFilters
		}
	}

	suspend fun setLastSelectedSeed(seedName: String?) {
		context.dataStore.edit { settings ->
			when (seedName) {
				is String -> settings[lastSelectedKeySet] = seedName
				null -> settings -= lastSelectedKeySet
			}
		}
	}

	suspend fun getLastSelectedSeed(): String? {
		return context.dataStore.data.first()[lastSelectedKeySet]
	}

	/**
	 * Flow for observing online mode setting.
	 * When enabled, the app will not enforce airgap (airplane mode, WiFi off, etc.)
	 * This is an opt-in feature for users who want to use the signer with network enabled.
	 */
	val onlineModeEnabled: Flow<Boolean> = context.dataStore.data
		.map { preferences ->
			preferences[onlineModeEnabledKey] ?: false
		}

	/**
	 * Get current online mode setting synchronously
	 */
	suspend fun isOnlineModeEnabled(): Boolean {
		return context.dataStore.data.first()[onlineModeEnabledKey] ?: false
	}

	/**
	 * Set online mode enabled/disabled
	 */
	suspend fun setOnlineModeEnabled(enabled: Boolean) {
		context.dataStore.edit { settings ->
			settings[onlineModeEnabledKey] = enabled
		}
	}
}
