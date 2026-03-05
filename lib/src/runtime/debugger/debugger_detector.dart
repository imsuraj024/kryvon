import '../channels/runtime_channel.dart';
import 'debugger_detection_result.dart';

/// Bridges Dart to the native debugger-detection logic via [RuntimeChannel].
///
/// Detection is performed in native Kotlin (`DebuggerDetector.kt`). This class
/// deserialises the platform response into a [DebuggerDetectionResult].
class DebuggerDetector {
  const DebuggerDetector();

  /// Queries the native layer and returns the [DebuggerDetectionResult].
  Future<DebuggerDetectionResult> check() async {

    final response = await RuntimeChannel.checkDebugger();

    final rawIndicators =
        response["indicators"] as List<dynamic>? ?? [];

    final indicators =
        rawIndicators.map((e) => e.toString()).toList();

    return DebuggerDetectionResult(
      indicators: indicators,
    );
  }
}