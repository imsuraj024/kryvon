import '../channels/runtime_channel.dart';
import 'debugger_detection_result.dart';

class DebuggerDetector {

  const DebuggerDetector();

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