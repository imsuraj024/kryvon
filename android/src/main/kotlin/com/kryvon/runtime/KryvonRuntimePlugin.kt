package com.kryvon.runtime

import android.content.Context
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

class KryvonRuntimePlugin : FlutterPlugin, MethodChannel.MethodCallHandler {

    private lateinit var channel: MethodChannel
    private lateinit var context: Context

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, "com.kryvon.runtime")
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        // Echo the nonce back so the Dart bridge can validate response authenticity.
        val nonce = call.argument<String>("__nonce")

        fun withNonce(payload: Map<String, Any?>): Map<String, Any?> =
            if (nonce != null) payload + ("__nonce" to nonce) else payload

        when (call.method) {
            "checkRoot" -> result.success(withNonce(RootDetector(context).checkRoot()))
            "checkDebugger" -> result.success(withNonce(DebuggerDetector(context).checkDebugger()))
            "checkHook" -> result.success(withNonce(HookDetector(context).checkHook()))
            "checkEmulator" -> result.success(withNonce(EmulatorDetector(context).checkEmulator()))
            "checkIntegrity" -> {
                val expectedSha256 = call.argument<String>("expectedSha256")
                result.success(withNonce(IntegrityDetector(context).checkIntegrity(expectedSha256)))
            }
            else -> result.notImplemented()
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }
}