import 'dart:io';
import '../internal/logger.dart';
import 'enforcement_strategy.dart';
import 'threat_event.dart';

class EnforcementExecutor {
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