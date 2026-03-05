package com.kryvon.runtime

import android.content.Context
import android.os.Build
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

class RootDetector(private val context: Context) {

    fun checkRoot(): Map<String, Any> {
        val indicators = mutableListOf<String>()

        if (hasSuBinary()) {
            indicators.add("suBinary")
        }

        if (canExecuteSu()) {
            indicators.add("suExecution")
        }

        if (hasTestKeys()) {
            indicators.add("testKeys")
        }

        if (hasDangerousSystemProperties()) {
            indicators.add("dangerousProps")
        }

        if (hasWritableSystemPartition()) {
            indicators.add("writableSystem")
        }

        if (hasKnownRootApps()) {
            indicators.add("knownRootApp")
        }

        return mapOf(
            "indicators" to indicators
        )
    }

    private fun hasSuBinary(): Boolean {
        val paths = arrayOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/vendor/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su"
        )

        return paths.any { File(it).exists() }
    }

    private fun canExecuteSu(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", "which su"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val result = reader.readLine()
            result != null
        } catch (e: Exception) {
            false
        }
    }

    private fun hasTestKeys(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun hasDangerousSystemProperties(): Boolean {
        val dangerousProps = mapOf(
            "ro.debuggable" to "1",
            "ro.secure" to "0"
        )

        return try {
            val process = Runtime.getRuntime().exec("getprop")
            val reader = BufferedReader(InputStreamReader(process.inputStream))

            reader.useLines { lines ->
                lines.any { line ->
                    dangerousProps.any { (key, value) ->
                        line.contains(key) && line.contains(value)
                    }
                }
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun hasWritableSystemPartition(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("mount")
            val reader = BufferedReader(InputStreamReader(process.inputStream))

            reader.useLines { lines ->
                lines.any { line ->
                    line.contains(" /system ") && line.contains(" rw,")
                }
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun hasKnownRootApps(): Boolean {
        val knownPackages = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser"
        )

        return knownPackages.any {
            try {
                context.packageManager.getPackageInfo(it, 0)
                true
            } catch (e: Exception) {
                false
            }
        }
    }
}