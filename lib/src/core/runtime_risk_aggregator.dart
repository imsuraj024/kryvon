import 'severity.dart';
import 'threat_event.dart';

/// Combines individual [ThreatEvent]s into a single aggregated [ThreatSeverity].
///
/// The algorithm assigns a numeric score per event (low=1, medium=3, high=6,
/// critical=10) and adds a diversity bonus of +2 for each unique [ThreatType]
/// present. The final score is then mapped back to a [ThreatSeverity]:
///
/// | Score  | Severity  |
/// |--------|-----------|
/// | < 3    | low       |
/// | 3–5    | medium    |
/// | 6–9    | high      |
/// | ≥ 10   | critical  |
class RuntimeRiskAggregator {
  const RuntimeRiskAggregator();

  static int _score(ThreatSeverity severity) {
    switch (severity) {
      case ThreatSeverity.low:
        return 1;
      case ThreatSeverity.medium:
        return 3;
      case ThreatSeverity.high:
        return 6;
      case ThreatSeverity.critical:
        return 10;
    }
  }

  /// Computes the aggregated [ThreatSeverity] from [events].
  ///
  /// Returns [ThreatSeverity.low] when [events] is empty.
  static ThreatSeverity aggregate(List<ThreatEvent> events) {
    if (events.isEmpty) return ThreatSeverity.low;

    int totalScore = 0;

    for (final event in events) {
      totalScore += _score(event.severity);
    }

    final uniqueThreats =
      events.map((e) => e.type).toSet().length;

    final diversityBonus = uniqueThreats * 2;

    final finalScore = totalScore + diversityBonus;

    if (finalScore >= 10) return ThreatSeverity.critical;
    if (finalScore >= 6) return ThreatSeverity.high;
    if (finalScore >= 3) return ThreatSeverity.medium;

    return ThreatSeverity.low;
  }
}