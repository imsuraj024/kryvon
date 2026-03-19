import 'package:kryvon/src/core/enforcement_strategy.dart';

import 'threat_event.dart';
import 'threat_type.dart';
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
///     expectedSignatureSha256: 'abc123...', // your release certificate hash
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
  /// Defaults to [EnforcementStrategy.emitOnly]. For critical threats such as
  /// [ThreatType.hookDetected] and [ThreatType.integrityFailure], the
  /// per-type strategy returned by [strategyForType] takes precedence.
  final EnforcementStrategy enforcementStrategy;

  /// Expected SHA-256 hex digest of the app's signing certificate.
  ///
  /// When set, [IntegrityGuard] compares the live certificate against this
  /// value. A mismatch produces a [ThreatType.integrityFailure] event.
  /// Leave `null` to skip certificate verification.
  final String? expectedSignatureSha256;

  /// Called once for every individual [ThreatEvent] produced by a guard.
  ///
  /// Use this to forward threat data to your analytics or alerting pipeline.
  final ThreatHandler? onThreat;

  const KryvonPolicy({
    this.blockThreshold = ThreatSeverity.high,
    this.enforcementStrategy = EnforcementStrategy.emitOnly,
    this.expectedSignatureSha256,
    this.onThreat,
  });

  /// Returns `true` when [event] meets or exceeds [blockThreshold].
  bool shouldBlock(ThreatEvent event) {
    return event.severity.index >= blockThreshold.index;
  }

  /// Returns the [EnforcementStrategy] to apply immediately for [type].
  ///
  /// Hook and integrity threats are always blocked outright regardless of
  /// the global [enforcementStrategy], because any leniency towards a live
  /// hooking framework or a tampered binary is unacceptable.
  /// Root threats restrict features. All other types fall back to
  /// [enforcementStrategy].
  EnforcementStrategy strategyForType(ThreatType type) {
    switch (type) {
      case ThreatType.hookDetected:
      case ThreatType.integrityFailure:
        return EnforcementStrategy.blockApp;
      case ThreatType.rootDetected:
        return EnforcementStrategy.restrictFeatures;
      default:
        return enforcementStrategy;
    }
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