import 'package:kryvon/src/runtime/channels/runtime_channel.dart';
import 'emulator_detection_result.dart';

/// Dart-side bridge for native emulator detection.
class EmulatorDetector {
  const EmulatorDetector();

  Future<EmulatorDetectionResult> check() async {
    final response = await RuntimeChannel.checkEmulator();

    if (response['__compromised'] == true) {
      // Channel failure on emulator check is suspicious but not as severe
      // as a hook — return clean result and let HookGuard handle it.
      return const EmulatorDetectionResult(
        emulatorDetected: false,
        indicators: [],
      );
    }

    final raw = response['indicators'];
    final indicators = raw is List
        ? raw.map((e) => e.toString()).toList()
        : <String>[];

    return EmulatorDetectionResult(
      emulatorDetected: indicators.isNotEmpty,
      indicators: indicators,
    );
  }
}
