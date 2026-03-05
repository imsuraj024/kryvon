import '../../core/guard.dart';
import '../../core/severity.dart';
import '../../core/threat_event.dart';
import '../../core/threat_type.dart';
import '../../internal/logger.dart';
import 'debugger_detector.dart';

class DebuggerGuard implements Guard {

  final DebuggerDetector _detector;

  DebuggerGuard({DebuggerDetector? detector})
      : _detector = detector ?? const DebuggerDetector();

  @override
  Future<List<ThreatEvent>> check() async {

    try {

      final result = await _detector.check();

      if (!result.debuggerAttached) {
        KryvonLogger.debug("DebuggerGuard: no debugger attached");
        return [];
      }

      KryvonLogger.warning(
        "DebuggerGuard: debugger detected",
      );

      return [
        ThreatEvent(
          type: ThreatType.debuggerDetected,
          severity: ThreatSeverity.medium,
          metadata: {
            "debuggerAttached": true
          },
        )
      ];

    } catch (e) {

      KryvonLogger.error(
        "DebuggerGuard failed",
        metadata: {"error": e.toString()},
      );

      return [];
    }
  }
}