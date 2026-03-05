import 'package:kryvon/src/core/enforcement_strategy.dart';

import 'threat_event.dart';
import 'severity.dart';

/// Callback invoked for each individual [ThreatEvent] detected during a check.
typedef ThreatHandler = void Function(ThreatEvent event);

/// Configures Kryvon's detection thresholds and response behaviour.
///
/// Pass an instance to [Kryvon.initialize]. The same policy governs all
/// guards registered in that session.
///
/// ```dart
/// Kryvon.initialize(
///   policy: KryvonPolicy(
///     blockThreshold: ThreatSeverity.high,
///     enforcementStrategy: EnforcementStrategy.terminateApp,
///     onThreat: (event) => analytics.log(event.type.name),
///   ),
/// );
/// ```
class KryvonPolicy {
  /// Minimum aggregated severity that triggers enforcement.
  ///
  /// Defaults to [ThreatSeverity.high]. Events below this threshold still
  /// fire [onThreat] but do not invoke [EnforcementExecutor].
  final ThreatSeverity blockThreshold;

  /// How Kryvon responds when the aggregated risk exceeds [blockThreshold].
  ///
  /// Defaults to [EnforcementStrategy.emitOnly].
  final EnforcementStrategy enforcementStrategy;

  /// Called once for every individual [ThreatEvent] produced by a guard.
  ///
  /// Use this to forward threat data to your analytics or alerting pipeline.
  final ThreatHandler? onThreat;

  const KryvonPolicy({
    this.blockThreshold = ThreatSeverity.high,
    this.enforcementStrategy = EnforcementStrategy.emitOnly,
    this.onThreat,
  });

  /// Returns `true` when [event] meets or exceeds [blockThreshold].
  bool shouldBlock(ThreatEvent event) {
    return event.severity.index >= blockThreshold.index;
  }

  /// Pre-configured policy suitable for fintech and high-security apps.
  ///
  /// Blocks on [ThreatSeverity.medium] and terminates the application when
  /// the threshold is exceeded.
  factory KryvonPolicy.fintech() {
    return const KryvonPolicy(
      blockThreshold: ThreatSeverity.medium,
      enforcementStrategy: EnforcementStrategy.terminateApp,
    );
  }
}