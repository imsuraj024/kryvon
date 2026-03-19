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
      case EnforcementStrategy.blockApp:
        _terminate(event);
        break;

      case EnforcementStrategy.restrictFeatures:
        _restrict(event);
        break;
    }
  }

  static void _terminate(ThreatEvent event) {
    KryvonLogger.error(
      "Application blocked due to security policy",
      metadata: {
        "threatType": event.type.name,
        "severity": event.severity.name,
      },
    );
    exit(1);
  }

  static void _restrict(ThreatEvent event) {
    KryvonLogger.warning(
      "Application features restricted due to security policy",
      metadata: {
        "threatType": event.type.name,
        "severity": event.severity.name,
      },
    );
    // Feature restriction is signalled via the onThreat callback.
    // The host app is responsible for gating sensitive flows.
  }
}