import 'severity.dart';
import 'threat_event.dart';
import 'threat_type.dart';

/// Combines individual [ThreatEvent]s into a single aggregated [ThreatSeverity].
///
/// Each [ThreatType] carries a base risk score reflecting its severity:
///
/// | Threat type        | Base score |
/// |--------------------|------------|
/// | hookDetected       | 50         |
/// | integrityFailure   | 50         |
/// | rootDetected       | 30         |
/// | debuggerDetected   | 20         |
/// | emulatorDetected   | 20         |
/// | (other)            | 5          |
///
/// The total score is mapped to [ThreatSeverity]:
///
/// | Score  | Severity  |
/// |--------|-----------|
/// | < 20   | low       |
/// | 20–29  | medium    |
/// | 30–49  | high      |
/// | ≥ 50   | critical  |
class RuntimeRiskAggregator {
  const RuntimeRiskAggregator();

  static int _typeScore(ThreatType type) {
    switch (type) {
      case ThreatType.hookDetected:
        return 50;
      case ThreatType.integrityFailure:
        return 50;
      case ThreatType.rootDetected:
        return 30;
      case ThreatType.debuggerDetected:
        return 20;
      case ThreatType.emulatorDetected:
        return 20;
      default:
        return 5;
    }
  }

  /// Computes the aggregated [ThreatSeverity] from [events].
  ///
  /// Returns [ThreatSeverity.low] when [events] is empty.
  static ThreatSeverity aggregate(List<ThreatEvent> events) {
    if (events.isEmpty) return ThreatSeverity.low;

    int totalScore = 0;
    for (final event in events) {
      totalScore += _typeScore(event.type);
    }

    if (totalScore >= 50) return ThreatSeverity.critical;
    if (totalScore >= 30) return ThreatSeverity.high;
    if (totalScore >= 20) return ThreatSeverity.medium;
    return ThreatSeverity.low;
  }
}