package net.rotko.zigner.screens.initial.splash

import android.content.Context
import androidx.lifecycle.ViewModel
import net.rotko.zigner.dependencygraph.ServiceLocator
import net.rotko.zigner.domain.NetworkState
import net.rotko.zigner.screens.initial.termsconsent.OnBoardingViewModel


class SplashScreenViewModel : ViewModel() {

	fun shouldShowSingleRunChecks(context: Context): Boolean {
		return OnBoardingViewModel.shouldShowSingleRunChecks(context)
	}

	fun isShouldShowAirgap(): Boolean {
		return ServiceLocator.networkExposedStateKeeper.airGapModeState.value != NetworkState.Active
	}

}
