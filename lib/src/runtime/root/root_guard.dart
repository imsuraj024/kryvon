
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

      KryvonLogger.warning(
        "RootGuard: root indicators detected",
        metadata: {
          "indicators":
              result.indicators.map((e) => e.name).toList(),
        },
      );

      return [
        ThreatEvent(
          type: ThreatType.rootDetected,
          severity: _mapSeverity(result.indicators),
          metadata: {
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
      indicators.contains(RootIndicatorType.dangerousProps)) {
    return ThreatSeverity.high;
  }

  return ThreatSeverity.medium;
}
}