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

      if (!result.debuggerDetected) {
        KryvonLogger.debug(
            "DebuggerGuard: no debugger detected");
        return [];
      }

      final severity = _calculateSeverity(result.indicators);

      KryvonLogger.warning(
        "DebuggerGuard: debugger detected",
        metadata: {
          "indicators": result.indicators
        },
      );

      return [
        ThreatEvent(
          type: ThreatType.debuggerDetected,
          severity: severity,
          metadata: {
            "indicators": result.indicators
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

  ThreatSeverity _calculateSeverity(List<String> indicators) {

    if (indicators.contains("tracerPid")) {
      return ThreatSeverity.critical;
    }

    if (indicators.contains("androidDebugger")) {
      return ThreatSeverity.high;
    }

    if (indicators.contains("jdwpEnabled")) {
      return ThreatSeverity.medium;
    }

    if (indicators.contains("debuggableApp")) {
      return ThreatSeverity.medium;
    }

    return ThreatSeverity.low;
  }
}