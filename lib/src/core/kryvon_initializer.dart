import 'package:kryvon/src/core/enforcement_executor.dart';
import 'package:kryvon/src/core/runtime_risk_aggregator.dart';
import 'package:kryvon/src/core/threat_event.dart';
import 'package:kryvon/src/core/threat_type.dart';
import 'package:kryvon/src/internal/log_level.dart';
import 'package:kryvon/src/internal/logger.dart';
import 'package:kryvon/src/runtime/root/root_guard.dart';

import 'guard.dart';
import 'kryvon_policy.dart';

class Kryvon {
  static late KryvonPolicy _policy;
  static final List<Guard> _guards = [];

  static void initialize({
    required KryvonPolicy policy,
    LogLevel logLevel = LogLevel.info,
  }) {
    _policy = policy;
    KryvonLogger.configure(level: logLevel);
    
    // Auto-register root guard
    if (!_guards.any((g) => g is RootGuard)) {
      registerGuard(RootGuard());
    }

    KryvonLogger.info("Kryvon initialized");
  }

  static void registerGuard(Guard guard) {
    _guards.add(guard);
    KryvonLogger.debug("Registered guards count: ${_guards.length}");
  }

static Future<void> runChecks() async {
  KryvonLogger.debug("Running security guards");

  final List<ThreatEvent> events = [];

  for (final guard in _guards) {
    try {
      final result = await guard.check();
      events.addAll(result);

      for (final event in result) {
        KryvonLogger.threat(event);
        _policy.onThreat?.call(event);
      }

    } catch (e) {
      KryvonLogger.error(
        "Guard execution failed",
        metadata: {"error": e.toString()},
      );
    }
  }

  final aggregatedSeverity =
      RuntimeRiskAggregator.aggregate(events);

  KryvonLogger.info(
    "Aggregated device risk",
    metadata: {"severity": aggregatedSeverity.name},
  );

  final aggregatedEvent = ThreatEvent(
    type: ThreatType.deviceCompromised,
    severity: aggregatedSeverity,
    metadata: {
      "events": events.map((e) => e.type.name).toList(),
    },
  );

  if (_policy.shouldBlock(aggregatedEvent)) {
    EnforcementExecutor.execute(
      strategy: _policy.enforcementStrategy,
      event: aggregatedEvent,
    );
  }
}
}