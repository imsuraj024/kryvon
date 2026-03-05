import '../channels/runtime_channel.dart';
import 'debugger_detection_result.dart';

class DebuggerDetector {
  const DebuggerDetector();

  Future<DebuggerDetectionResult> check() async {
    final response = await RuntimeChannel.checkDebugger();

    final bool attached =
        response['debuggerAttached'] as bool;

    return DebuggerDetectionResult(
      debuggerAttached: attached,
    );
  }
}