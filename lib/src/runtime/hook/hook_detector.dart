import 'package:kryvon/src/runtime/channels/runtime_channel.dart';
import 'hook_detection_result.dart';

/// Dart-side bridge for native hook detection.
///
/// Delegates all actual detection to the Kotlin [HookDetector] via
/// [RuntimeChannel]. A `__compromised` flag in the native response is treated
/// as a hook indicator, because a healthy runtime should always return a valid
/// response.
class HookDetector {
  const HookDetector();

  Future<HookDetectionResult> check() async {
    final response = await RuntimeChannel.checkHook();

    // Fail-secure: if the native layer is unresponsive or returns garbage,
    // assume the runtime has been tampered with.
    if (response['__compromised'] == true) {
      return const HookDetectionResult(
        hookDetected: true,
        indicators: ['channelCompromised'],
      );
    }

    final raw = response['indicators'];
    final indicators = raw is List
        ? raw.map((e) => e.toString()).toList()
        : <String>[];

    return HookDetectionResult(
      hookDetected: indicators.isNotEmpty,
      indicators: indicators,
    );
  }
}
