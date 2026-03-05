import 'dart:io';
import '../internal/logger.dart';
import 'enforcement_strategy.dart';
import 'threat_event.dart';

/// Carries out the enforcement action dictated by [EnforcementStrategy].
///
/// This class is used internally by [Kryvon.runChecks] and is not intended
/// to be called directly by application code.
class EnforcementExecutor {
  /// Executes [strategy] in response to [event].
  ///
  /// - [EnforcementStrategy.emitOnly] — does nothing beyond logging.
  /// - [EnforcementStrategy.terminateApp] — calls `exit(1)` after logging.
  static void execute({
    required EnforcementStrategy strategy,
    required ThreatEvent event,
  }) {
    switch (strategy) {
      case EnforcementStrategy.emitOnly:
        // No enforcement
        break;

      case EnforcementStrategy.terminateApp:
        _terminate(event);
        break;
    }
  }

  static void _terminate(ThreatEvent event) {
    KryvonLogger.error(
      "Application terminated due to security policy",
      metadata: {
        "threatType": event.type.name,
        "severity": event.severity.name,
      },
    );

    // Android-safe termination
    exit(1);
  }
}