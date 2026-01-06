package net.rotko.zigner.domain.security

import android.content.Context

/**
 * Unified security checker combining:
 * - Hardware attestation (device integrity)
 * - Memory protection (MTE)
 * - Sealed secrets (key binding)
 *
 * Call before signing operations to verify device security state.
 */
object SecurityChecker {

    data class SecurityStatus(
        val overallSecure: Boolean,
        val attestation: AttestationStatus,
        val memory: MemoryStatus,
        val secrets: SecretsStatus,
        val summary: String
    )

    data class AttestationStatus(
        val available: Boolean,
        val verified: Boolean,
        val bootSecure: Boolean,
        val securityLevel: String
    )

    data class MemoryStatus(
        val mteSupported: Boolean,
        val mteActive: Boolean,
        val mode: String
    )

    data class SecretsStatus(
        val available: Boolean,
        val strongBoxBacked: Boolean,
        val biometricBound: Boolean
    )

    /**
     * Perform comprehensive security check.
     * Returns detailed status of all security mechanisms.
     */
    fun checkSecurity(context: Context): SecurityStatus {
        val attestation = checkAttestation(context)
        val memory = checkMemory()
        val secrets = checkSecrets(context)

        // Overall security: TEE/StrongBox available is minimum
        val overallSecure = attestation.verified || secrets.strongBoxBacked

        val summary = buildSecuritySummary(attestation, memory, secrets)

        return SecurityStatus(
            overallSecure = overallSecure,
            attestation = attestation,
            memory = memory,
            secrets = secrets,
            summary = summary
        )
    }

    private fun checkAttestation(context: Context): AttestationStatus {
        val hasSecurity = DeviceAttestation.hasHardwareSecurity(context)
        val meetsRequirements = DeviceAttestation.meetsSecurityRequirements(context)
        val description = DeviceAttestation.getSecurityDescription(context)

        return AttestationStatus(
            available = hasSecurity,
            verified = meetsRequirements,
            bootSecure = true, // Assume true until full attestation performed
            securityLevel = description
        )
    }

    private fun checkMemory(): MemoryStatus {
        val status = MemoryProtection.getMteStatus()

        return MemoryStatus(
            mteSupported = status.hardwareSupported,
            mteActive = status.mode != MemoryProtection.MteMode.OFF &&
                       status.mode != MemoryProtection.MteMode.UNKNOWN,
            mode = status.description
        )
    }

    private fun checkSecrets(context: Context): SecretsStatus {
        val props = SealedSecrets.getSecurityProperties(context)

        return SecretsStatus(
            available = SealedSecrets.isAvailable(),
            strongBoxBacked = props.isStrongBoxBacked,
            biometricBound = props.invalidatedByBiometricEnrollment
        )
    }

    private fun buildSecuritySummary(
        attestation: AttestationStatus,
        memory: MemoryStatus,
        secrets: SecretsStatus
    ): String {
        val parts = mutableListOf<String>()

        // Key storage
        when {
            secrets.strongBoxBacked -> parts.add("StrongBox")
            attestation.verified -> parts.add("TEE")
            else -> parts.add("Software only")
        }

        // Memory protection
        if (memory.mteActive) {
            parts.add("MTE")
        }

        // Biometric binding
        if (secrets.biometricBound) {
            parts.add("Bio-bound")
        }

        return parts.joinToString(" + ")
    }

    /**
     * Quick check if device meets minimum security for signing.
     * Returns false if signing would be insecure.
     */
    fun meetsMinimumRequirements(context: Context): Boolean {
        return DeviceAttestation.meetsSecurityRequirements(context)
    }

    /**
     * Get user-friendly security description for display.
     */
    fun getSecurityDescription(context: Context): String {
        val status = checkSecurity(context)
        return status.summary
    }

    /**
     * Get detailed security report for display.
     */
    fun getDetailedReport(context: Context): List<Pair<String, String>> {
        val status = checkSecurity(context)

        return listOf(
            "Key Storage" to status.attestation.securityLevel,
            "Memory Protection" to status.memory.mode,
            "Biometric Binding" to if (status.secrets.biometricBound) "Enabled" else "Disabled",
            "Overall" to if (status.overallSecure) "Secure" else "Reduced Security"
        )
    }
}
