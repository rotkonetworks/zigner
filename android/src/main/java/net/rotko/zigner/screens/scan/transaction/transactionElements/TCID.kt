package net.rotko.zigner.screens.scan.transaction.transactionElements

import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import net.rotko.zigner.ui.theme.SignerTypeface

@Composable
fun TCID(base58: String) {
	Text(
		text = base58,
		style = SignerTypeface.BodyL,
		color = MaterialTheme.colors.primary
	)
}
