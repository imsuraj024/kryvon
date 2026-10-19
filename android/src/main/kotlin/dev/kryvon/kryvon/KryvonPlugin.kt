package dev.kryvon.kryvon

import android.os.Debug
import android.system.ErrnoException
import android.system.Os
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

class KryvonPlugin : FlutterPlugin, MethodChannel.MethodCallHandler {
    private lateinit var channel: MethodChannel
    private lateinit var evaluator: AndroidSignalEvaluator

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        evaluator = AndroidSignalEvaluator(
            pathProbe = AndroidPathProbe(),
            debuggerProbe = DebuggerProbe { Debug.isDebuggerConnected() }
        )
        channel = MethodChannel(binding.binaryMessenger, CHANNEL_NAME)
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "getCapabilities" -> {
                val args = call.arguments as? Map<*, *>
                val requestId = args?.get("requestId") as? String
                if (args?.get("protocolVersion") != PROTOCOL_VERSION ||
                    requestId.isNullOrBlank()
                ) {
                    result.error("invalid_request", "Invalid protocol request.", null)
                    return
                }
                result.success(
                    mapOf(
                        "protocolVersion" to PROTOCOL_VERSION,
                        "requestId" to requestId,
                        "platform" to "android",
                        "capabilities" to listOf(
                            AndroidSignalEvaluator.ROOT_SU_SIGNAL,
                            AndroidSignalEvaluator.DEBUGGER_SIGNAL
                        )
                    )
                )
            }
            "evaluateSignal" -> evaluate(call, result)
            else -> result.notImplemented()
        }
    }

    private fun evaluate(call: MethodCall, result: MethodChannel.Result) {
        val args = call.arguments as? Map<*, *>
        val requestId = args?.get("requestId") as? String
        val signalId = args?.get("signalId") as? String
        val context = args?.get("context") as? String
        val configuration = args?.get("configuration")
        if (args?.get("protocolVersion") != PROTOCOL_VERSION ||
            requestId.isNullOrBlank() ||
            signalId.isNullOrBlank() ||
            context.isNullOrBlank() ||
            configuration !is Map<*, *> ||
            configuration.isNotEmpty()
        ) {
            result.error("invalid_request", "Invalid protocol request.", null)
            return
        }

        try {
            val observation = evaluator.evaluate(signalId)
            val response: Map<String, Any?> = if (observation == null) {
                mapOf(
                    "status" to "unsupported",
                    "confidence" to null,
                    "source" to "android.platform",
                    "metadata" to mapOf("diagnosticCode" to "unsupported_signal")
                )
            } else {
                mapOf(
                    "status" to observation.status,
                    "confidence" to observation.confidence,
                    "source" to observation.source,
                    "metadata" to observation.metadata
                )
            }
            result.success(
                response + mapOf(
                    "protocolVersion" to PROTOCOL_VERSION,
                    "requestId" to requestId,
                    "signalId" to signalId,
                    "platform" to "android",
                    "observedAt" to utcTimestamp()
                )
            )
        } catch (_: Exception) {
            result.success(
                mapOf(
                    "protocolVersion" to PROTOCOL_VERSION,
                    "requestId" to requestId,
                    "signalId" to signalId,
                    "status" to "failed",
                    "confidence" to null,
                    "source" to "android.platform",
                    "platform" to "android",
                    "observedAt" to utcTimestamp(),
                    "metadata" to mapOf("diagnosticCode" to "native_check_failure")
                )
            )
        }
    }

    private fun utcTimestamp(): String {
        val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        format.timeZone = TimeZone.getTimeZone("UTC")
        return format.format(Date())
    }

    private class AndroidPathProbe : PathProbe {
        override fun inspect(path: String): ProbeResult {
            return try {
                val stat = Os.stat(path)
                if (isExecutableRegularFile(stat.st_mode)) {
                    ProbeResult.EXECUTABLE_PRESENT
                } else {
                    ProbeResult.ABSENT
                }
            } catch (error: ErrnoException) {
                classifyPathStatError(error.errno)
            } catch (_: SecurityException) {
                ProbeResult.ERROR
            }
        }
    }

    companion object {
        private const val CHANNEL_NAME = "dev.kryvon/security.v1"
        private const val PROTOCOL_VERSION = 1
    }
}
