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
        when (call.method) {
            "checkRoot" -> result.success(RootDetector(context).checkRoot())
            "checkDebugger" -> result.success(DebuggerDetector(context).checkDebugger())
            "checkHook" -> result.success(HookDetector(context).checkHook())
            "checkEmulator" -> result.success(EmulatorDetector(context).checkEmulator())
            "checkIntegrity" -> {
                val expectedSha256 = call.argument<String>("expectedSha256")
                result.success(IntegrityDetector(context).checkIntegrity(expectedSha256))
            }
            else -> result.notImplemented()
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }
}