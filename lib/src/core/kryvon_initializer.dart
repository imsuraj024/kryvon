import 'package:kryvon/src/core/enforcement_executor.dart';
import 'package:kryvon/src/core/runtime_risk_aggregator.dart';
import 'package:kryvon/src/core/threat_event.dart';
import 'package:kryvon/src/core/threat_type.dart';
import 'package:kryvon/src/internal/log_level.dart';
import 'package:kryvon/src/internal/logger.dart';
import 'package:kryvon/src/runtime/debugger/debugger_guard.dart';
import 'package:kryvon/src/runtime/root/root_guard.dart';

import 'guard.dart';
import 'kryvon_policy.dart';

/// Primary entry point for the Kryvon security framework.
///
/// Call [initialize] once at app startup (e.g. in `main()`), then call
/// [runChecks] whenever you want to evaluate the device's security posture —
/// typically on app resume or before sensitive operations.
///
/// ```dart
/// await Kryvon.initialize(policy: KryvonPolicy.fintech());
/// await Kryvon.runChecks();
/// ```
class Kryvon {
  static late KryvonPolicy _policy;
  static final List<Guard> _guards = [];

  /// Configures Kryvon with the supplied [policy] and [logLevel].
  ///
  /// Auto-registers [RootGuard] and [DebuggerGuard]. Must be called before
  /// [runChecks].
  static void initialize({
    required KryvonPolicy policy,
    LogLevel logLevel = LogLevel.info,
  }) {
    _policy = policy;
    KryvonLogger.configure(level: logLevel);

    // Auto-register root guard
    if (!_guards.any((g) => g is RootGuard || g is DebuggerGuard)) {
      registerGuard(RootGuard());
      registerGuard(DebuggerGuard());
    }

    KryvonLogger.info("Kryvon initialized");
  }

  /// Registers a custom [Guard] to be run alongside the built-in guards.
  ///
  /// Must be called after [initialize] and before [runChecks].
  static void registerGuard(Guard guard) {
    _guards.add(guard);
    KryvonLogger.debug("Registered guards count: ${_guards.length}");
  }

  /// Runs all registered guards in parallel and enforces policy on the result.
  ///
  /// For each guard that detects a threat, [KryvonPolicy.onThreat] is called
  /// with the individual [ThreatEvent]. After all guards complete, the events
  /// are aggregated by [RuntimeRiskAggregator] into a single
  /// [ThreatType.deviceCompromised] event. If the aggregated severity meets or
  /// exceeds [KryvonPolicy.blockThreshold], [EnforcementExecutor] is invoked
  /// with the configured [EnforcementStrategy].
  static Future<void> runChecks() async {
    KryvonLogger.debug("Running security guards");

    try {
      final futures = _guards.map((guard) async {
        try {
          return await guard.check();
        } catch (e) {
          KryvonLogger.error(
            "Guard execution failed",
            metadata: {"guard": guard.runtimeType.toString(), "error": e.toString()},
          );
          return <ThreatEvent>[];
        }
      });

      final results = await Future.wait(futures);

      final List<ThreatEvent> allEvents = results.expand((e) => e).toList();

      for (final event in allEvents) {
        KryvonLogger.threat(event);
        _policy.onThreat?.call(event);
      }

      final aggregatedSeverity =
          RuntimeRiskAggregator.aggregate(allEvents);

      KryvonLogger.info(
        "Aggregated device risk",
        metadata: {"severity": aggregatedSeverity.name},
      );

      final aggregatedEvent = ThreatEvent(
        type: ThreatType.deviceCompromised,
        severity: aggregatedSeverity,
        metadata: {
          "events": allEvents.map((e) => e.type.name).toList(),
        },
      );

      if (_policy.shouldBlock(aggregatedEvent)) {
        EnforcementExecutor.execute(
          strategy: _policy.enforcementStrategy,
          event: aggregatedEvent,
        );
      }
    } catch (e) {
      KryvonLogger.error(
        "Kryvon runtime check failed",
        metadata: {"error": e.toString()},
      );
    }
  }

}