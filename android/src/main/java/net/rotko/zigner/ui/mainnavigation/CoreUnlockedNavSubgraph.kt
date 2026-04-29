package net.rotko.zigner.ui.mainnavigation

import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.core.tween
import androidx.compose.runtime.Composable
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import net.rotko.zigner.screens.createderivation.DerivationCreateSubgraph
import net.rotko.zigner.screens.error.errorStateDestination
import net.rotko.zigner.screens.keydetails.KeyDetailsScreenSubgraph
import net.rotko.zigner.screens.keysetdetails.keySetDetailsDestination
import net.rotko.zigner.screens.keysets.create.NewKeysetSubgraph
import net.rotko.zigner.screens.keysets.restore.KeysetRecoverSubgraph
import net.rotko.zigner.screens.scan.ScanNavSubgraph
import net.rotko.zigner.screens.scan.bananasplitcreate.bananaSplitCreateDestination
import net.rotko.zigner.screens.settings.backupexport.BackupExportSubgraph
import net.rotko.zigner.screens.settings.frost.FrostWalletListScreen
import net.rotko.zigner.screens.settings.networks.helper.networkHelpersCoreSubgraph
import net.rotko.zigner.screens.settings.settingsFullSubgraph

@Composable
fun CoreUnlockedNavSubgraph(navController: NavHostController) {

	NavHost(
		navController = navController,
		startDestination = CoreUnlockedNavSubgraph.KeySet.destination(null),
		enterTransition = {
			slideIntoContainer(
				AnimatedContentTransitionScope.SlideDirection.Start,
				animationSpec = tween()
			)
		},
		exitTransition = {
			ExitTransition.None
		},
		popEnterTransition = {
			EnterTransition.None
		},
		popExitTransition = {
			slideOutOfContainer(
				AnimatedContentTransitionScope.SlideDirection.End,
				animationSpec = tween()
			)
		}
	) {
		keySetDetailsDestination(navController)
		composable(CoreUnlockedNavSubgraph.newKeySet) {
			NewKeysetSubgraph(
				coreNavController = navController,
			)
		}
		composable(CoreUnlockedNavSubgraph.recoverKeySet) {
			KeysetRecoverSubgraph(
				coreNavController = navController
			)
		}
		bananaSplitCreateDestination(navController)
		composable(
			route = CoreUnlockedNavSubgraph.BackupExport.route,
			arguments = listOf(
				navArgument(CoreUnlockedNavSubgraph.BackupExport.seedNameArg) {
					type = NavType.StringType
				}
			)
		) {
			val seedName =
				it.arguments?.getString(CoreUnlockedNavSubgraph.BackupExport.seedNameArg)!!
			BackupExportSubgraph(
				seedName = seedName,
				onClose = { navController.popBackStack() }
			)
		}
		composable(
			route = CoreUnlockedNavSubgraph.KeyDetails.route,
			arguments = listOf(
				navArgument(CoreUnlockedNavSubgraph.KeyDetails.argKeyAddr) {
					type = NavType.StringType
				},
				navArgument(CoreUnlockedNavSubgraph.KeyDetails.argKeySpec) {
					type = NavType.StringType
				},
			)
		) {
			val keyAddr =
				it.arguments?.getString(CoreUnlockedNavSubgraph.KeyDetails.argKeyAddr)!!
			val keySpec =
				it.arguments?.getString(CoreUnlockedNavSubgraph.KeyDetails.argKeySpec)!!
			KeyDetailsScreenSubgraph(
				navController = navController,
				keyAddr = keyAddr,
				keySpec = keySpec
			)
		}
		composable(
			route = CoreUnlockedNavSubgraph.NewDerivedKey.route,
			arguments = listOf(
				navArgument(CoreUnlockedNavSubgraph.NewDerivedKey.seedNameArg) {
					type = NavType.StringType
				}
			),
		) {
			val seedName =
				it.arguments?.getString(CoreUnlockedNavSubgraph.KeySet.seedName)!!

			DerivationCreateSubgraph(
				onBack = { navController.popBackStack() },
				onOpenCamera = {
					navController.navigate(
						CoreUnlockedNavSubgraph.Camera.destination(
							null
						)
					)
				},
				seedName = seedName,
			)
		}
		composable(
			CoreUnlockedNavSubgraph.Camera.route,
			enterTransition = {
				slideIntoContainer(
					AnimatedContentTransitionScope.SlideDirection.Up,
					animationSpec = tween()
				)
			},
			exitTransition = {
				slideOutOfContainer(
					AnimatedContentTransitionScope.SlideDirection.Down,
					animationSpec = tween()
				)
			},
			arguments = listOf(
				navArgument(CoreUnlockedNavSubgraph.Camera.bsKeysetArg) {
					type = NavType.StringType
					nullable = true
				}
			)
		) {
			val bsKeysetValue =
				it.arguments?.getString(CoreUnlockedNavSubgraph.Camera.bsKeysetArg)

			ScanNavSubgraph(
				onCloseCamera = {
					navController.popBackStack()
				},
				seedNameSuggestion = bsKeysetValue,
				openKeySet = { seedName ->
					navController.navigate(
						CoreUnlockedNavSubgraph.KeySet.destination(
							seedNameValue = seedName
						)
					)
				}
			)
		}
		composable(CoreUnlockedNavSubgraph.frostWalletList) {
			FrostWalletListScreen(
				onBack = { navController.popBackStack() },
			)
		}
		settingsFullSubgraph(
			coreNavController = navController,
		)
		networkHelpersCoreSubgraph(
			navController = navController,
		)
		errorStateDestination(
			navController = navController,
		)
	}
}

object CoreUnlockedNavSubgraph {
	const val newKeySet = "core_new_keyset"
	const val recoverKeySet = "keyset_recover_flow"

	object Camera {
		internal const val bsKeysetArg = "seed_name_arg"
		private const val baseRoute = "unlocked_camera"
		const val route = "$baseRoute?$bsKeysetArg={$bsKeysetArg}" //optional
		fun destination(bsKeysetValue: String?): String {
			val result =
				if (bsKeysetValue == null) baseRoute else "$baseRoute?$bsKeysetArg=${bsKeysetValue}"
			return result
		}
	}

	object CreateBananaSplit {
		internal const val seedNameArg = "seed_name_arg"
		private const val baseRoute = "banana_split_create"
		const val route = "$baseRoute/{$seedNameArg}"
		fun destination(seedName: String) = "$baseRoute/$seedName"
	}

	object KeySet {
		internal const val seedName = "seed_name_arg"
		private const val baseRoute = "core_keyset_details_home"
		const val route = "$baseRoute?$seedName={$seedName}" //optional
		fun destination(seedNameValue: String?): String {
			val result =
				if (seedNameValue == null) baseRoute else "$baseRoute?$seedName=${seedNameValue}"
			return result
		}
	}

	object NewDerivedKey {
		internal const val seedNameArg = "seed_name_arg"
		private const val baseRoute = "core_new_keyset"
		const val route = "$baseRoute/{${seedNameArg}}"
		fun destination(seedName: String) = "$baseRoute/${seedName}"
	}

	object KeyDetails {
		internal const val argKeyAddr = "key_addr"
		internal const val argKeySpec = "key_spec"
		private const val baseRoute = "core_key_details_home"
		const val route = "$baseRoute/{$argKeyAddr}/{$argKeySpec}"
		fun destination(keyAddr: String, keySpec: String) =
			"$baseRoute/$keyAddr/$keySpec"
	}

	object ErrorScreenGeneral {
		internal const val argHeader = "key_header"
		internal const val argDescription = "key_descr"
		internal const val argVerbose = "key_verb"
		private const val baseRoute = "core_error_state"
		const val route = "$baseRoute/{$argHeader}/{$argDescription}/{$argVerbose}"
		fun destination(
			argHeader: String,
			argDescription: String,
			argVerbose: String
		) =
			"$baseRoute/$argHeader/$argDescription/$argVerbose"
	}

	object BackupExport {
		internal const val seedNameArg = "seed_name_arg"
		private const val baseRoute = "backup_export"
		const val route = "$baseRoute/{$seedNameArg}"
		fun destination(seedName: String) = "$baseRoute/$seedName"
	}

	const val errorWrongDbVersionUpdate = "core_wrong_version_mismatch"

	const val airgapBreached = "core_airgap_blocker"
	const val settings = "core_settings_flow"
	const val networkHelpers = "network_helpers_path"
	const val frostWalletList = "frost_wallet_list"
}
