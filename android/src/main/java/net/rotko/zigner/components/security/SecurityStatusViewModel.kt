package net.rotko.zigner.components.security

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import net.rotko.zigner.domain.security.DeviceAttestation
import net.rotko.zigner.domain.security.MemoryProtection
import net.rotko.zigner.domain.security.SecurityChecker

/**
 * ViewModel for providing security status to UI components.
 */
class SecurityStatusViewModel(application: Application) : AndroidViewModel(application) {

    private val _securityStatus = MutableStateFlow<SecurityDisplayStatus?>(null)
    val securityStatus: StateFlow<SecurityDisplayStatus?> = _securityStatus.asStateFlow()

    init {
        refreshSecurityStatus()
    }

    fun refreshSecurityStatus() {
        val context = getApplication<Application>()
        val status = SecurityChecker.checkSecurity(context)
        val mteStatus = MemoryProtection.getMteStatus()
        val isMteActive = mteStatus.mode != MemoryProtection.MteMode.OFF &&
                         mteStatus.mode != MemoryProtection.MteMode.UNKNOWN

        val level = when {
            status.secrets.strongBoxBacked && isMteActive -> SecurityLevel.SECURE
            status.attestation.verified || status.secrets.strongBoxBacked -> {
                if (mteStatus.hardwareSupported && !isMteActive) {
                    SecurityLevel.WARNING
                } else {
                    SecurityLevel.SECURE
                }
            }
            status.overallSecure -> SecurityLevel.WARNING
            else -> SecurityLevel.INSECURE
        }

        val summary = buildSummary(status, mteStatus)
        val details = buildDetails(status, mteStatus)

        _securityStatus.value = SecurityDisplayStatus(
            level = level,
            summary = summary,
            details = details
        )
    }

    private fun buildSummary(
        status: SecurityChecker.SecurityStatus,
        mteStatus: MemoryProtection.MteStatus
    ): String {
        val parts = mutableListOf<String>()
        val isMteActive = mteStatus.mode != MemoryProtection.MteMode.OFF &&
                         mteStatus.mode != MemoryProtection.MteMode.UNKNOWN

        // Key storage
        if (status.secrets.strongBoxBacked) {
            parts.add("StrongBox")
        } else if (status.attestation.verified) {
            parts.add("TEE")
        } else {
            parts.add("Software")
        }

        // MTE
        if (isMteActive) {
            parts.add("MTE")
        }

        // Biometric
        if (status.secrets.biometricBound) {
            parts.add("Bio")
        }

        return parts.joinToString(" + ")
    }

    private fun buildDetails(
        status: SecurityChecker.SecurityStatus,
        mteStatus: MemoryProtection.MteStatus
    ): List<SecurityDetail> {
        val isMteActive = mteStatus.mode != MemoryProtection.MteMode.OFF &&
                         mteStatus.mode != MemoryProtection.MteMode.UNKNOWN

        return listOf(
            SecurityDetail(
                label = "Key Storage",
                value = status.attestation.securityLevel,
                isSecure = status.secrets.strongBoxBacked || status.attestation.verified
            ),
            SecurityDetail(
                label = "Memory Protection",
                value = mteStatus.description,
                isSecure = isMteActive
            ),
            SecurityDetail(
                label = "Biometric Binding",
                value = if (status.secrets.biometricBound) "Enabled" else "Disabled",
                isSecure = status.secrets.biometricBound
            ),
            SecurityDetail(
                label = "Device Unlock Required",
                value = if (status.secrets.available) "Yes" else "No",
                isSecure = status.secrets.available
            )
        )
    }

    /**
     * Get security status for display in transaction screens.
     * Returns a compact description.
     */
    fun getCompactStatus(): SecurityDisplayStatus {
        return _securityStatus.value ?: SecurityDisplayStatus(
            level = SecurityLevel.WARNING,
            summary = "Checking...",
            details = emptyList()
        )
    }

    /**
     * Check if device meets minimum security requirements for signing.
     */
    fun meetsMinimumRequirements(): Boolean {
        val context = getApplication<Application>()
        return SecurityChecker.meetsMinimumRequirements(context)
    }

    /**
     * Get description for why signing might be blocked.
     */
    fun getBlockingReason(): String? {
        val status = _securityStatus.value ?: return "Security status unknown"
        return when (status.level) {
            SecurityLevel.INSECURE -> "Device does not have hardware security. Signing is not recommended."
            SecurityLevel.WARNING -> null // Allow with warning
            SecurityLevel.SECURE -> null
        }
    }
}
