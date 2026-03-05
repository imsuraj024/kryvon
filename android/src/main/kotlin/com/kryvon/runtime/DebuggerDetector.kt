package com.kryvon.runtime

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Debug
import java.io.File

class DebuggerDetector(private val context: Context) {

    fun checkDebugger(): Map<String, Any> {

        val indicators = mutableListOf<String>()

        if (isAndroidDebuggerConnected()) {
            indicators.add("androidDebugger")
        }

        if (isTracerPidPresent()) {
            indicators.add("tracerPid")
        }

        if (isJdwpEnabled()) {
            indicators.add("jdwpEnabled")
        }

        if (isAppDebuggable()) {
            indicators.add("debuggableApp")
        }

        return mapOf(
            "indicators" to indicators
        )
    }

    private fun isAndroidDebuggerConnected(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }

    private fun isTracerPidPresent(): Boolean {
        return try {
            val file = File("/proc/self/status")

            if (!file.exists()) return false

            val lines = file.readLines()

            for (line in lines) {
                if (line.startsWith("TracerPid")) {
                    val parts = line.split("\\s+".toRegex())
                    val tracerPid = parts.last().toInt()
                    return tracerPid > 0
                }
            }

            false
        } catch (e: Exception) {
            false
        }
    }

    private fun isJdwpEnabled(): Boolean {
        return try {

            val process = Runtime.getRuntime().exec("ps")

            val output = process.inputStream.bufferedReader().readText()

            output.contains("jdwp")

        } catch (e: Exception) {
            false
        }
    }

    private fun isAppDebuggable(): Boolean {
        return (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }
}