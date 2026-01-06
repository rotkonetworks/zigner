package net.rotko.zigner.domain.security

import android.content.pm.ApplicationInfo
import android.os.Build
import timber.log.Timber
import java.io.File

/**
 * Memory Tagging Extension (MTE) support detection and status.
 *
 * MTE is available on ARM v8.5+ (Tensor G3, etc.) and provides:
 * - Detection of use-after-free bugs
 * - Detection of buffer overflows
 * - Hardware-enforced memory safety
 *
 * For Zigner, MTE protects the signing operation when seeds are in RAM.
 */
object MemoryProtection {

    data class MteStatus(
        val hardwareSupported: Boolean,
        val appEnabled: Boolean,
        val mode: MteMode,
        val description: String
    )

    enum class MteMode {
        SYNC,   // Synchronous - immediate detection, higher overhead
        ASYNC,  // Asynchronous - eventual detection, lower overhead
        OFF,    // Disabled
        UNKNOWN
    }

    /**
     * Check if MTE is supported and enabled.
     */
    fun getMteStatus(): MteStatus {
        val hardwareSupported = isHardwareSupported()
        val appEnabled = isAppMteEnabled()
        val mode = detectMteMode()

        val description = when {
            !hardwareSupported -> "Hardware does not support MTE"
            !appEnabled -> "MTE not enabled for this app"
            mode == MteMode.SYNC -> "MTE active (synchronous)"
            mode == MteMode.ASYNC -> "MTE active (asynchronous)"
            else -> "MTE status unknown"
        }

        return MteStatus(
            hardwareSupported = hardwareSupported,
            appEnabled = appEnabled,
            mode = mode,
            description = description
        )
    }

    /**
     * Check if CPU supports MTE (ARM v8.5+).
     * Reads /proc/cpuinfo for MTE feature flag.
     */
    private fun isHardwareSupported(): Boolean {
        // MTE requires Android 12+ (API 31)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return false
        }

        return try {
            val cpuinfo = File("/proc/cpuinfo").readText()
            // Look for MTE in Features line
            cpuinfo.lines()
                .filter { it.startsWith("Features") }
                .any { it.contains("mte") }
        } catch (e: Exception) {
            Timber.d("Could not read cpuinfo: ${e.message}")
            // Alternative: check for known MTE-capable SoCs
            isMteCapableSoc()
        }
    }

    /**
     * Check for known MTE-capable SoCs by model.
     */
    private fun isMteCapableSoc(): Boolean {
        val model = Build.MODEL.lowercase()
        val hardware = Build.HARDWARE.lowercase()

        // Tensor G3 (Pixel 8/8 Pro/8a), G4 (Pixel 9 series)
        // These are the primary targets for Zigner
        return hardware.contains("zuma") ||      // Tensor G3
               hardware.contains("shiba") ||     // Pixel 8
               hardware.contains("husky") ||     // Pixel 8 Pro
               hardware.contains("akita") ||     // Pixel 8a
               hardware.contains("comet") ||     // Tensor G4
               model.contains("pixel 8") ||
               model.contains("pixel 9")
    }

    /**
     * Check if app has MTE enabled via manifest.
     * We set android:memtagMode="sync" in AndroidManifest.xml
     */
    private fun isAppMteEnabled(): Boolean {
        // The app has memtagMode="sync" in manifest
        // At runtime, we can check /proc/self/status for tagged_addr_ctrl
        return try {
            val status = File("/proc/self/status").readText()
            status.contains("MemTag:")
        } catch (e: Exception) {
            // If we can't read, assume it's enabled if hardware supports
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
        }
    }

    /**
     * Detect which MTE mode is active.
     */
    private fun detectMteMode(): MteMode {
        return try {
            val status = File("/proc/self/status").readText()
            val memtagLine = status.lines().find { it.startsWith("MemTag:") }

            when {
                memtagLine == null -> MteMode.OFF
                memtagLine.contains("1") -> MteMode.ASYNC
                memtagLine.contains("2") -> MteMode.SYNC
                memtagLine.contains("3") -> MteMode.SYNC // sync + async
                else -> MteMode.UNKNOWN
            }
        } catch (e: Exception) {
            Timber.d("Could not detect MTE mode: ${e.message}")
            MteMode.UNKNOWN
        }
    }

    /**
     * Get security description for display.
     */
    fun getSecurityDescription(): String {
        val status = getMteStatus()
        return when {
            status.mode == MteMode.SYNC -> "Memory protected (MTE sync)"
            status.mode == MteMode.ASYNC -> "Memory protected (MTE async)"
            status.hardwareSupported && !status.appEnabled -> "MTE available but not active"
            !status.hardwareSupported -> "Memory protection unavailable"
            else -> "Memory protection status unknown"
        }
    }

    /**
     * Check if memory protection meets security requirements.
     * For highest security, we want MTE in sync mode.
     */
    fun meetsSecurityRequirements(): Boolean {
        val status = getMteStatus()
        // Accept any active MTE mode
        return status.mode == MteMode.SYNC || status.mode == MteMode.ASYNC
    }
}
