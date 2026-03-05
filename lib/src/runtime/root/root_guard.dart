
import 'package:kryvon/src/core/guard.dart';

import 'package:kryvon/src/core/threat_event.dart';
import 'package:kryvon/src/core/threat_type.dart';
import 'package:kryvon/src/core/severity.dart';
import 'package:kryvon/src/internal/logger.dart';
import 'package:kryvon/src/runtime/root/root_indicator.dart';
import 'root_detection_result.dart';
import 'root_detector.dart';

class RootGuard implements Guard {
  final RootDetector _detector;

  RootGuard({RootDetector? detector})
      : _detector = detector ?? const RootDetector();

  @override
  Future<List<ThreatEvent>> check() async {
    KryvonLogger.debug("RootGuard check started");
    try {
      final RootDetectionResult result = await _detector.check();

      if (!result.isRooted) {
        KryvonLogger.debug("RootGuard: device not rooted");
        return [];
      }

      final ThreatSeverity severity = _mapSeverity(result.indicators);

      KryvonLogger.warning(
        "RootGuard: root indicators detected",
        metadata: {
          "severity": severity.name,
          "indicators":
              result.indicators.map((e) => e.name).toList(),
        },
      );

      return [
        ThreatEvent(
          type: ThreatType.rootDetected,
          severity: severity,
          metadata: {
            "severity": severity.name,
            "indicators":
                result.indicators.map((e) => e.name).toList(),
                
          },
        ),
      ];
    } catch (e) {
      KryvonLogger.error(
        "RootGuard failed",
        metadata: {"error": e.toString()},
      );

      return [];
    }
  }

  ThreatSeverity _mapSeverity(List<RootIndicatorType> indicators) {
  if (indicators.contains(RootIndicatorType.suExecution)) {
    return ThreatSeverity.critical;
  }

  if (indicators.contains(RootIndicatorType.suBinary) ||
      indicators.contains(RootIndicatorType.dangerousProps) ||
      indicators.contains(RootIndicatorType.writableSystem)) {
    return ThreatSeverity.high;
  }

  if (indicators.contains(RootIndicatorType.knownRootApp) ||
      indicators.contains(RootIndicatorType.testKeys)) {
    return ThreatSeverity.medium;
  }

  return ThreatSeverity.low;
}
}