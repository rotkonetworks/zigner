package net.rotko.zigner.components.security

import android.content.res.Configuration.UI_MODE_NIGHT_NO
import android.content.res.Configuration.UI_MODE_NIGHT_YES
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.Icon
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Shield
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import net.rotko.zigner.components.base.SecondaryButtonWide
import net.rotko.zigner.domain.Callback
import net.rotko.zigner.ui.theme.*

/**
 * Detailed security information bottom sheet.
 * Shows all security features and their status.
 */
@Composable
fun SecurityDetailsBottomSheet(
    status: SecurityDisplayStatus,
    close: Callback,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        // Header icon
        Box(
            modifier = Modifier
                .padding(vertical = 24.dp)
                .size(80.dp)
                .clip(RoundedCornerShape(40.dp))
                .background(
                    when (status.level) {
                        SecurityLevel.SECURE -> MaterialTheme.colors.Crypto400.copy(alpha = 0.15f)
                        SecurityLevel.WARNING -> MaterialTheme.colors.accentPink.copy(alpha = 0.15f)
                        SecurityLevel.INSECURE -> MaterialTheme.colors.red400.copy(alpha = 0.15f)
                    }
                ),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = null,
                tint = when (status.level) {
                    SecurityLevel.SECURE -> MaterialTheme.colors.Crypto400
                    SecurityLevel.WARNING -> MaterialTheme.colors.accentPink
                    SecurityLevel.INSECURE -> MaterialTheme.colors.red400
                },
                modifier = Modifier.size(40.dp)
            )
        }

        // Title
        Text(
            text = when (status.level) {
                SecurityLevel.SECURE -> "Device Security: Strong"
                SecurityLevel.WARNING -> "Device Security: Reduced"
                SecurityLevel.INSECURE -> "Device Security: Weak"
            },
            color = MaterialTheme.colors.primary,
            style = SignerTypeface.TitleL,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp),
        )

        Spacer(modifier = Modifier.height(8.dp))

        // Summary
        Text(
            text = status.summary,
            color = MaterialTheme.colors.textSecondary,
            style = SignerTypeface.BodyL,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp),
        )

        Spacer(modifier = Modifier.height(24.dp))

        // Details list
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            status.details.forEach { detail ->
                SecurityDetailRow(detail)
            }
        }

        SecondaryButtonWide(
            label = "Got it",
            modifier = Modifier.padding(horizontal = 32.dp, vertical = 24.dp),
            withBackground = true,
        ) {
            close()
        }
    }
}

@Composable
private fun SecurityDetailRow(detail: SecurityDetail) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colors.fill6)
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = detail.label,
                style = SignerTypeface.LabelM,
                color = MaterialTheme.colors.textTertiary
            )
            Text(
                text = detail.value,
                style = SignerTypeface.BodyL,
                color = MaterialTheme.colors.primary
            )
        }

        Icon(
            imageVector = if (detail.isSecure) Icons.Default.CheckCircle else Icons.Default.Close,
            contentDescription = null,
            tint = if (detail.isSecure) MaterialTheme.colors.Crypto400 else MaterialTheme.colors.red400,
            modifier = Modifier.size(24.dp)
        )
    }
}

@Preview(
    name = "light", group = "themes", uiMode = UI_MODE_NIGHT_NO,
    showBackground = true, backgroundColor = 0xFFFFFFFF,
)
@Preview(
    name = "dark", group = "themes", uiMode = UI_MODE_NIGHT_YES,
    showBackground = true, backgroundColor = 0xFF000000,
)
@Composable
private fun PreviewSecurityDetailsBottomSheetSecure() {
    SignerNewTheme {
        SecurityDetailsBottomSheet(
            status = SecurityDisplayStatus(
                level = SecurityLevel.SECURE,
                summary = "Your device has strong hardware security. Keys are protected by the secure element.",
                details = listOf(
                    SecurityDetail("Key Storage", "StrongBox (Titan M2)", true),
                    SecurityDetail("Memory Protection", "MTE Active (sync)", true),
                    SecurityDetail("Biometric Binding", "Enabled", true),
                    SecurityDetail("Boot State", "Verified", true)
                )
            ),
            close = {}
        )
    }
}

@Preview(
    name = "warning", group = "states", uiMode = UI_MODE_NIGHT_NO,
    showBackground = true, backgroundColor = 0xFFFFFFFF,
)
@Composable
private fun PreviewSecurityDetailsBottomSheetWarning() {
    SignerNewTheme {
        SecurityDetailsBottomSheet(
            status = SecurityDisplayStatus(
                level = SecurityLevel.WARNING,
                summary = "Your device has hardware security but some features are unavailable.",
                details = listOf(
                    SecurityDetail("Key Storage", "TEE (no StrongBox)", true),
                    SecurityDetail("Memory Protection", "Unavailable", false),
                    SecurityDetail("Biometric Binding", "Enabled", true),
                    SecurityDetail("Boot State", "Unknown", false)
                )
            ),
            close = {}
        )
    }
}
