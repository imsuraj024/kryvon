package dev.kryvon.kryvon

/**
 * Pure signal semantics, separated from Android APIs so partial failures can be
 * tested deterministically on the JVM.
 */
internal enum class ProbeResult { EXECUTABLE_PRESENT, ABSENT, ERROR }

internal fun interface PathProbe {
    fun inspect(path: String): ProbeResult
}

internal fun interface DebuggerProbe {
    fun isDebuggerAttached(): Boolean
}

internal data class SignalObservation(
    val status: String,
    val confidence: String?,
    val source: String,
    val metadata: Map<String, Any?> = emptyMap()
)

internal class AndroidSignalEvaluator(
    private val pathProbe: PathProbe,
    private val debuggerProbe: DebuggerProbe,
    private val suPaths: List<String> = DEFAULT_SU_PATHS
) {
    fun evaluate(signalId: String): SignalObservation? = when (signalId) {
        ROOT_SU_SIGNAL -> evaluateSuPaths()
        DEBUGGER_SIGNAL -> evaluateDebugger()
        else -> null
    }

    private fun evaluateSuPaths(): SignalObservation {
        var failures = 0
        var candidateFound = false
        for (path in suPaths) {
            when (pathProbe.inspect(path)) {
                ProbeResult.EXECUTABLE_PRESENT -> candidateFound = true
                ProbeResult.ABSENT -> Unit
                ProbeResult.ERROR -> failures += 1
            }
        }

        if (candidateFound) {
            return SignalObservation(
                status = "detected",
                confidence = "medium",
                source = "android.filesystem.su_probe",
                metadata = mapOf(
                    "indicatorCode" to "known_su_executable_path",
                    "pathsChecked" to suPaths.size,
                    "partialCheckFailures" to failures
                )
            )
        }
        if (failures > 0) {
            return SignalObservation(
                status = "failed",
                confidence = null,
                source = "android.filesystem.su_probe",
                metadata = mapOf(
                    "diagnosticCode" to "partial_path_check_failure",
                    "pathsChecked" to suPaths.size,
                    "failedPathChecks" to failures
                )
            )
        }
        return SignalObservation(
            status = "not_detected",
            confidence = "high",
            source = "android.filesystem.su_probe",
            metadata = mapOf(
                "indicatorCode" to "no_known_su_executable_path",
                "pathsChecked" to suPaths.size,
                "partialCheckFailures" to 0
            )
        )
    }

    private fun evaluateDebugger(): SignalObservation = try {
        SignalObservation(
            status = if (debuggerProbe.isDebuggerAttached()) "detected" else "not_detected",
            confidence = "high",
            source = "android.platform.debugger_api",
            metadata = mapOf("observationCode" to "debugger_attached_api")
        )
    } catch (_: Exception) {
        SignalObservation(
            status = "failed",
            confidence = null,
            source = "android.platform.debugger_api",
            metadata = mapOf("diagnosticCode" to "debugger_api_failure")
        )
    }

    companion object {
        const val ROOT_SU_SIGNAL = "android.root.su_binary_present"
        const val DEBUGGER_SIGNAL = "android.debugger.attached"

        // Fixed, reviewed paths. Never accept caller-provided paths: configuration
        // must not silently weaken or broaden the security check.
        val DEFAULT_SU_PATHS = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/sbin/su",
            "/vendor/bin/su",
            "/su/bin/su",
            "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su",
            "/system/bin/failsafe/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su"
        )
    }
}
