package net.rotko.zigner.screens.keysets.restore

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.backend.RecoverSeedInteractor
import net.rotko.zigner.domain.backend.mapError
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class KeysetRecoverViewModel : ViewModel() {

	private val backendInteractor = RecoverSeedInteractor()

	private val _recoverSeed = MutableStateFlow<KeysetRecoverModel>(
		KeysetRecoverModel.new(getGuessWordsSync(""))
	)
	val recoverSeed = _recoverSeed.asStateFlow()

	val existingSeeds = ServiceLocator.seedStorage.lastKnownSeedNames

	private fun getGuessWordsSync(input: String): List<String> {
		return runBlocking {
			backendInteractor.seedPhraseGuessWords(input).mapError() ?: emptyList()
		}
	}

	private suspend fun getGuessWords(input: String): List<String> {
		return backendInteractor.seedPhraseGuessWords(input).mapError() ?: emptyList()
	}

	private suspend fun validateSeedPhraseAsync(phrase: List<String>): Boolean {
		return backendInteractor.validateSeedPhrase(phrase.joinToString(separator = " "))
			.mapError() ?: false
	}

	fun onUserInput(rawUserInput: String) {
		if (_recoverSeed.value.enteredWords.size > KeysetRecoverModel.WORDS_CAP) {
			_recoverSeed.update {
				it.copy(rawUserInput = KeysetRecoverModel.SPACE_CHARACTER.toString())
			}
			return
		}

		if (rawUserInput.isEmpty()) {
			_recoverSeed.update {
				it.copy(
					rawUserInput = KeysetRecoverModel.SPACE_CHARACTER.toString(),
					enteredWords = it.enteredWords.dropLast(1)
				)
			}
			return
		}

		if (rawUserInput.first() != KeysetRecoverModel.SPACE_CHARACTER) {
			_recoverSeed.update {
				it.copy(
					rawUserInput = KeysetRecoverModel.SPACE_CHARACTER.toString() + rawUserInput,
				)
			}
			return
		}

		// Always accept the input immediately so the text field stays responsive
		_recoverSeed.update {
			it.copy(rawUserInput = rawUserInput)
		}

		// Fetch suggestions asynchronously
		val input = rawUserInput.trim().lowercase()
		viewModelScope.launch {
			val guessing = getGuessWords(input)
			if (rawUserInput.length > 1 && rawUserInput.endsWith(KeysetRecoverModel.SPACE_CHARACTER)) {
				if (guessing.contains(input)) {
					onAddword(input)
				}
			} else {
				_recoverSeed.update {
					it.copy(suggestedWords = guessing)
				}
			}
		}
	}

	fun onAddword(word: String) {
		_recoverSeed.update {
			val newDraft = it.enteredWords + word
			it.copy(
				rawUserInput = KeysetRecoverModel.SPACE_CHARACTER.toString(),
				enteredWords = newDraft,
				suggestedWords = emptyList()
			)
		}
		// Validate and refresh suggestions async
		viewModelScope.launch {
			val newDraft = _recoverSeed.value.enteredWords
			val valid = validateSeedPhraseAsync(newDraft)
			val suggestions = getGuessWords("")
			_recoverSeed.update {
				it.copy(
					validSeed = valid,
					suggestedWords = suggestions
				)
			}
		}
	}
}


data class KeysetRecoverModel(
	val rawUserInput: String,
	val suggestedWords: List<String>,
	val enteredWords: List<String>,
	val validSeed: Boolean
) {
	companion object {

		// Maximum word count in `bip39` standard.
		// See <https://docs.rs/tiny-bip39/0.8.2/src/bip39/mnemonic_type.rs.html#60>
		const val WORDS_CAP: Int = 24;

		const val SPACE_CHARACTER: Char = ' '
		const val NEW_LINE: Char = '\n'

		fun new(suggestedWords: List<String>): KeysetRecoverModel {
			return KeysetRecoverModel(
				rawUserInput = SPACE_CHARACTER.toString(),
				suggestedWords = suggestedWords,
				enteredWords = emptyList(),
				validSeed = false,
			)
		}

		fun stub(): KeysetRecoverModel {
			return KeysetRecoverModel(
				rawUserInput = "ggf",
				suggestedWords = listOf("ggfhg", "goha"),
				enteredWords = listOf("somve", "words", "that", "are", "draft"),
				validSeed = false,
			)
		}
	}
}
