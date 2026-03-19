import 'package:kryvon/src/core/guard.dart';
import 'package:kryvon/src/core/kryvon_policy.dart';
import 'package:kryvon/src/core/severity.dart';
import 'package:kryvon/src/core/threat_event.dart';
import 'package:kryvon/src/core/threat_type.dart';
import 'package:kryvon/src/internal/logger.dart';

import 'integrity_detector.dart';

/// [Guard] that verifies the app's signing certificate and package integrity.
///
/// When [KryvonPolicy.expectedSignatureSha256] is set, the live certificate
/// SHA-256 is compared against it natively. A mismatch indicates repackaging
/// or certificate substitution and triggers a [ThreatSeverity.critical] event.
///
/// Auto-registered by [Kryvon.initialize].
class IntegrityGuard implements Guard {
  final IntegrityDetector _detector;
  final KryvonPolicy _policy;

  IntegrityGuard({
    required KryvonPolicy policy,
    IntegrityDetector? detector,
  })  : _policy = policy,
        _detector = detector ?? const IntegrityDetector();

  @override
  Future<List<ThreatEvent>> check() async {
    KryvonLogger.debug("IntegrityGuard check started");
    try {
      final result = await _detector.check(
        expectedSignatureSha256: _policy.expectedSignatureSha256,
      );

      if (result.integrityOk) {
        KryvonLogger.debug(
          "IntegrityGuard: integrity verified",
          metadata: {"sha256": result.liveSha256 ?? "unavailable"},
        );
        return [];
      }

      KryvonLogger.warning(
        "IntegrityGuard: integrity failure",
        metadata: {
          "indicators": result.indicators,
          "liveSha256": result.liveSha256 ?? "unavailable",
        },
      );

      return [
        ThreatEvent(
          type: ThreatType.integrityFailure,
          severity: ThreatSeverity.critical,
          metadata: {
            "indicators": result.indicators,
            "liveSha256": result.liveSha256 ?? "unavailable",
          },
        ),
      ];
    } catch (e) {
      KryvonLogger.error(
        "IntegrityGuard failed",
        metadata: {"error": e.toString()},
      );
      // Fail-secure: a guard that cannot run cannot verify integrity.
      return [
        ThreatEvent(
          type: ThreatType.integrityFailure,
          severity: ThreatSeverity.critical,
          metadata: {"reason": "guard_execution_failed"},
        ),
      ];
    }
  }
}
