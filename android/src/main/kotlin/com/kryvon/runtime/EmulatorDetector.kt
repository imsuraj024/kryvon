package com.kryvon.runtime

import android.content.Context
import android.os.Build
import java.io.File

class EmulatorDetector(private val context: Context) {

    fun checkEmulator(): Map<String, Any> {
        val indicators = mutableListOf<String>()

        if (hasGenericFingerprint()) indicators.add("genericFingerprint")
        if (hasQemuProps()) indicators.add("qemuProps")
        if (hasEmulatorBuildProps()) indicators.add("emulatorBuildProps")
        if (hasEmulatorFiles()) indicators.add("emulatorFiles")
        if (hasGenymotion()) indicators.add("genymotion")

        return mapOf("indicators" to indicators)
    }

    /** Checks Build fields for well-known emulator fingerprints. */
    private fun hasGenericFingerprint(): Boolean {
        val fingerprint = Build.FINGERPRINT ?: return false
        return fingerprint.startsWith("generic") ||
               fingerprint.startsWith("unknown") ||
               fingerprint.contains("emulator") ||
               fingerprint.contains("sdk_gphone") ||
               fingerprint.contains("sdk_x86") ||
               Build.MODEL.contains("Emulator") ||
               Build.MODEL.contains("Android SDK built for x86") ||
               Build.HARDWARE.contains("goldfish") ||
               Build.HARDWARE.contains("ranchu") ||
               Build.PRODUCT.startsWith("sdk") ||
               Build.PRODUCT.contains("emulator") ||
               Build.BRAND.startsWith("generic") ||
               Build.DEVICE.startsWith("generic")
    }

    /** Reads ro.hardware via getprop; goldfish/ranchu are QEMU kernels. */
    private fun hasQemuProps(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", "ro.hardware"))
            val result = process.inputStream.bufferedReader().readLine()?.trim() ?: ""
            result.contains("goldfish") || result.contains("ranchu")
        } catch (e: Exception) {
            false
        }
    }

    /** Checks manufacturer/product/device Build fields for emulator strings. */
    private fun hasEmulatorBuildProps(): Boolean {
        return Build.MANUFACTURER.lowercase().contains("genymotion") ||
               Build.PRODUCT.lowercase().contains("vbox") ||
               Build.PRODUCT.lowercase().contains("sdk_gphone") ||
               Build.DEVICE.lowercase().contains("generic")
    }

    /** Looks for QEMU-specific device files that only exist inside emulators. */
    private fun hasEmulatorFiles(): Boolean {
        val qemuPaths = listOf(
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props"
        )
        return qemuPaths.any { File(it).exists() }
    }

    /** Checks for Genymotion-specific build properties. */
    private fun hasGenymotion(): Boolean {
        return Build.PRODUCT.lowercase().contains("vbox") ||
               Build.MANUFACTURER.lowercase().contains("genymotion")
    }
}
