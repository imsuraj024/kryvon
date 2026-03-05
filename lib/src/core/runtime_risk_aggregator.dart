import 'severity.dart';
import 'threat_event.dart';

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