package net.rotko.zigner.screens.initial.termsconsent

import android.content.Context
import androidx.lifecycle.ViewModel
import net.rotko.zigner.domain.isDbCreatedAndOnboardingPassed


class OnBoardingViewModel : ViewModel() {


	companion object {
		fun shouldShowSingleRunChecks(context: Context): Boolean {
			return !context.isDbCreatedAndOnboardingPassed()
		}
	}
}
