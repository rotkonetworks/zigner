package net.rotko.zigner.screens.initial.firstTimeOnly

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import androidx.navigation.navigation
import net.rotko.zigner.screens.initial.termsconsent.TermsConsentScreenFull
import net.rotko.zigner.ui.rootnavigation.MainGraphRoutes


fun NavGraphBuilder.firstTimeOnlyOnboarding(
	routePath: String,
	navController: NavHostController,
) {
	navigation(
		route = routePath,
		startDestination = FirstTimeOnboarding.termsConsentRoute,
	) {
		composable(route = FirstTimeOnboarding.termsConsentRoute) {
			TermsConsentScreenFull(
				navigateNextScreen = {
					navController.navigate(MainGraphRoutes.eachTimeOnboardingRoute) {
						popUpTo(0)
					}
				},
			)
		}
	}
}

private object FirstTimeOnboarding {
	//	const val onboardingExplanationRoute = "navigation_onboarding_explanation"
	const val termsConsentRoute = "navigation_point_terms_consent"
}
