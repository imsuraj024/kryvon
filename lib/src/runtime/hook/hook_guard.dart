import 'package:kryvon/src/core/guard.dart';
import 'package:kryvon/src/core/severity.dart';
import 'package:kryvon/src/core/threat_event.dart';
import 'package:kryvon/src/core/threat_type.dart';
import 'package:kryvon/src/internal/logger.dart';

import 'hook_detector.dart';

/// [Guard] that detects runtime hooking frameworks (Frida, Xposed, Substrate).
///
/// Any indicator triggers a [ThreatSeverity.critical] event because the
/// presence of a hooking framework renders all other security controls
/// untrustworthy.
///
/// Auto-registered by [Kryvon.initialize].
class HookGuard implements Guard {
  final HookDetector _detector;

  HookGuard({HookDetector? detector})
      : _detector = detector ?? const HookDetector();

  @override
  Future<List<ThreatEvent>> check() async {
    KryvonLogger.debug("HookGuard check started");
    try {
      final result = await _detector.check();

      if (!result.hookDetected) {
        KryvonLogger.debug("HookGuard: no hook indicators");
        return [];
      }

      KryvonLogger.warning(
        "HookGuard: hooking framework detected",
        metadata: {"indicators": result.indicators},
      );

      return [
        ThreatEvent(
          type: ThreatType.hookDetected,
          severity: ThreatSeverity.critical,
          metadata: {"indicators": result.indicators},
        ),
      ];
    } catch (e) {
      KryvonLogger.error(
        "HookGuard failed",
        metadata: {"error": e.toString()},
      );
      // Fail-secure: treat guard failure as a potential hook suppression.
      return [
        ThreatEvent(
          type: ThreatType.hookDetected,
          severity: ThreatSeverity.critical,
          metadata: {"reason": "guard_execution_failed"},
        ),
      ];
    }
  }
}
