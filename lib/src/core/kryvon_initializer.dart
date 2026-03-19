import 'package:kryvon/src/core/enforcement_executor.dart';
import 'package:kryvon/src/core/enforcement_strategy.dart';
import 'package:kryvon/src/core/runtime_risk_aggregator.dart';
import 'package:kryvon/src/core/severity.dart';
import 'package:kryvon/src/core/threat_event.dart';
import 'package:kryvon/src/core/threat_type.dart';
import 'package:kryvon/src/internal/log_level.dart';
import 'package:kryvon/src/internal/logger.dart';
import 'package:kryvon/src/runtime/debugger/debugger_guard.dart';
import 'package:kryvon/src/runtime/emulator/emulator_guard.dart';
import 'package:kryvon/src/runtime/hook/hook_guard.dart';
import 'package:kryvon/src/runtime/integrity/integrity_guard.dart';
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
  /// Auto-registers [RootGuard], [DebuggerGuard], [HookGuard],
  /// [EmulatorGuard], and [IntegrityGuard]. Must be called before [runChecks].
  static void initialize({
    required KryvonPolicy policy,
    LogLevel logLevel = LogLevel.info,
  }) {
    _policy = policy;
    KryvonLogger.configure(level: logLevel);

    if (_guards.isEmpty) {
      registerGuard(RootGuard());
      registerGuard(DebuggerGuard());
      registerGuard(HookGuard());
      registerGuard(EmulatorGuard());
      registerGuard(IntegrityGuard(policy: policy));
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
            "Guard execution failed — treating as compromise",
            metadata: {"guard": guard.runtimeType.toString(), "error": e.toString()},
          );
          // Fail-secure: an unexpected guard failure is treated as evidence
          // of hook-based suppression rather than a silent no-op.
          return <ThreatEvent>[
            ThreatEvent(
              type: ThreatType.hookDetected,
              severity: ThreatSeverity.critical,
              metadata: {
                "guard": guard.runtimeType.toString(),
                "reason": "guard_execution_failed",
              },
            ),
          ];
        }
      });

      final results = await Future.wait(futures);
      final List<ThreatEvent> allEvents = results.expand((e) => e).toList();

      for (final event in allEvents) {
        KryvonLogger.threat(event);
        _policy.onThreat?.call(event);

        // Enforce immediately for hook and integrity threats — do not wait
        // for aggregation, as these invalidate all other security controls.
        final immediateStrategy = _policy.strategyForType(event.type);
        if (immediateStrategy == EnforcementStrategy.blockApp) {
          EnforcementExecutor.execute(strategy: immediateStrategy, event: event);
          return;
        }
      }

      final aggregatedSeverity = RuntimeRiskAggregator.aggregate(allEvents);

      KryvonLogger.info(
        "Aggregated device risk",
        metadata: {"severity": aggregatedSeverity.name},
      );

      final aggregatedEvent = ThreatEvent(
        type: ThreatType.deviceCompromised,
        severity: aggregatedSeverity,
        metadata: {"events": allEvents.map((e) => e.type.name).toList()},
      );

      if (_policy.shouldBlock(aggregatedEvent)) {
        EnforcementExecutor.execute(
          strategy: _policy.enforcementStrategy,
          event: aggregatedEvent,
        );
      }
    } catch (e) {
      // Fail-secure: if the orchestrator itself throws, block immediately.
      KryvonLogger.error(
        "Kryvon runtime check failed — blocking app",
        metadata: {"error": e.toString()},
      );
      EnforcementExecutor.execute(
        strategy: EnforcementStrategy.blockApp,
        event: ThreatEvent(
          type: ThreatType.hookDetected,
          severity: ThreatSeverity.critical,
          metadata: {"reason": "orchestrator_failure"},
        ),
      );
    }
  }

}