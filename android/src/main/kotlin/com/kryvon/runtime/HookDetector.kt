package com.kryvon.runtime

import android.content.Context
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

class HookDetector(private val context: Context) {

    fun checkHook(): Map<String, Any> {
        val indicators = mutableListOf<String>()

        if (hasFridaProcess()) indicators.add("fridaProcess")
        if (hasFridaPort()) indicators.add("fridaPort")
        if (hasFridaLibrary()) indicators.add("fridaLibrary")
        if (hasXposedBridge()) indicators.add("xposedBridge")
        if (hasXposedModules()) indicators.add("xposedModules")

        return mapOf("indicators" to indicators)
    }

    /** Scans /proc/*/cmdline for known Frida process names. */
    private fun hasFridaProcess(): Boolean {
        return try {
            File("/proc").listFiles()?.any { procDir ->
                val cmdline = File(procDir, "cmdline")
                if (cmdline.exists() && cmdline.canRead()) {
                    val content = cmdline.readText().lowercase()
                    content.contains("frida") || content.contains("gadget")
                } else false
            } ?: false
        } catch (e: Exception) {
            false
        }
    }

    /** Attempts a TCP connection to the default Frida server ports. */
    private fun hasFridaPort(): Boolean {
        val ports = listOf(27042, 27043)
        return ports.any { port ->
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress("127.0.0.1", port), 100)
                    true
                }
            } catch (e: Exception) {
                false
            }
        }
    }

    /** Reads /proc/self/maps for Frida/Gadget/Substrate native library names. */
    private fun hasFridaLibrary(): Boolean {
        return try {
            val maps = File("/proc/self/maps")
            if (!maps.exists()) return false
            maps.readLines().any { line ->
                line.contains("frida") ||
                line.contains("gadget") ||
                line.contains("libsubstrate")
            }
        } catch (e: Exception) {
            false
        }
    }

    /** Attempts to load the Xposed bridge class via reflection. */
    private fun hasXposedBridge(): Boolean {
        return try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            true
        } catch (e: ClassNotFoundException) {
            false
        }
    }

    /** Attempts to load the Xposed method-hook class via reflection. */
    private fun hasXposedModules(): Boolean {
        return try {
            Class.forName("de.robv.android.xposed.XC_MethodHook")
            true
        } catch (e: ClassNotFoundException) {
            false
        }
    }
}
