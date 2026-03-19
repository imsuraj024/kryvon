import 'package:kryvon/src/core/guard.dart';
import 'package:kryvon/src/core/severity.dart';
import 'package:kryvon/src/core/threat_event.dart';
import 'package:kryvon/src/core/threat_type.dart';
import 'package:kryvon/src/internal/logger.dart';

import 'emulator_detector.dart';

/// [Guard] that detects Android emulators and virtual devices.
///
/// Emulator detection uses hardware fingerprints, QEMU-specific system
/// properties, and known emulator file paths. A positive result indicates
/// the app may be under automated analysis.
///
/// Auto-registered by [Kryvon.initialize].
class EmulatorGuard implements Guard {
  final EmulatorDetector _detector;

  EmulatorGuard({EmulatorDetector? detector})
      : _detector = detector ?? const EmulatorDetector();

  @override
  Future<List<ThreatEvent>> check() async {
    KryvonLogger.debug("EmulatorGuard check started");
    try {
      final result = await _detector.check();

      if (!result.emulatorDetected) {
        KryvonLogger.debug("EmulatorGuard: physical device confirmed");
        return [];
      }

      KryvonLogger.warning(
        "EmulatorGuard: emulator indicators detected",
        metadata: {"indicators": result.indicators},
      );

      return [
        ThreatEvent(
          type: ThreatType.emulatorDetected,
          severity: ThreatSeverity.medium,
          metadata: {"indicators": result.indicators},
        ),
      ];
    } catch (e) {
      KryvonLogger.error(
        "EmulatorGuard failed",
        metadata: {"error": e.toString()},
      );
      return [];
    }
  }
}
